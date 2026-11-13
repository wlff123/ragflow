package sensitive

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

type OriginalStorageConfig struct {
	Endpoint  string `yaml:"endpoint"`
	Region    string `yaml:"region"`
	Bucket    string `yaml:"bucket"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Prefix    string `yaml:"prefix"`
}

type originalClient interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// OriginalStore uses explicit credentials and a dedicated bucket; it never
// falls back to the knowledgebase storage factory or ambient AWS credentials.
type OriginalStore struct {
	client         originalClient
	bucket, prefix string
}

func NewOriginalStore(c OriginalStorageConfig) (*OriginalStore, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		c.Bucket == "" || c.Region == "" || c.AccessKey == "" || c.SecretKey == "" {
		return nil, Failure("SP_CONFIG_INVALID")
	}
	prefix := strings.Trim(c.Prefix, "/")
	if strings.Contains(prefix, "..") || strings.ContainsAny(prefix, "\\\r\n") {
		return nil, Failure("SP_CONFIG_INVALID")
	}
	client := s3.NewFromConfig(aws.Config{
		Region: c.Region, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, ""),
	}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(c.Endpoint)
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &OriginalStore{client: client, bucket: c.Bucket, prefix: prefix}, nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", Failure("SP_RESULT_SAVE_FAILED")
	}
	return hex.EncodeToString(b[:]), nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (s *OriginalStore) key(location string) (string, error) {
	parts := strings.Split(location, "/")
	if len(parts) != 3 || !validID(parts[0]) || !validID(parts[1]) || !validID(parts[2]) {
		return "", Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	if s.prefix != "" {
		return s.prefix + "/" + location, nil
	}
	return location, nil
}

func (s *OriginalStore) Check(ctx context.Context) error {
	if _, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)}); err != nil {
		return Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	return nil
}

// NewOriginalLocation allocates a key that the caller must persist before PUT.
func NewOriginalLocation(kbID, docID string) (string, error) {
	if !validID(kbID) || !validID(docID) {
		return "", Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	return kbID + "/" + docID + "/" + id, nil
}

// PutOriginal writes only to an already recorded location. An error does not
// imply that the object is absent: the caller must clean up this same location.
func (s *OriginalStore) PutOriginal(ctx context.Context, location, name string, body []byte) error {
	key, err := s.key(location)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(body),
		Metadata: map[string]string{"original-name": url.QueryEscape(name)}, ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	return nil
}

type Original struct {
	Body io.ReadCloser
	Name string
	Size int64
}

// OpenOriginal transfers ownership of Body to the caller, who must close it.
func (s *OriginalStore) OpenOriginal(ctx context.Context, location string) (*Original, error) {
	key, err := s.key(location)
	if err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	name, err := url.QueryUnescape(out.Metadata["original-name"])
	if err != nil || name == "" || out.Body == nil {
		if out.Body != nil {
			out.Body.Close()
		}
		return nil, Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	return &Original{Body: out.Body, Name: name, Size: aws.ToInt64(out.ContentLength)}, nil
}

func (s *OriginalStore) Exists(ctx context.Context, location string) (bool, error) {
	key, err := s.key(location)
	if err != nil {
		return false, err
	}
	_, err = s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err == nil {
		return true, nil
	}
	var api smithy.APIError
	if errors.As(err, &api) && (api.ErrorCode() == "NotFound" || api.ErrorCode() == "NoSuchKey") {
		return false, nil
	}
	return false, Failure("SP_ORIGINAL_UNAVAILABLE")
}

func (s *OriginalStore) Delete(ctx context.Context, location string) error {
	key, err := s.key(location)
	if err != nil {
		return err
	}
	if _, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}); err != nil {
		return Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	return nil
}
