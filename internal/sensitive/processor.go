package sensitive

import (
	"context"
	"os"
	"time"
)

type Settings struct {
	RulesPath         string
	MatchTimeout      time.Duration
	DocumentBudget    time.Duration
	MinimumCharacters int
	MinimumRatio      float64
	OriginalStorage   OriginalStorageConfig
}

// OriginalStorage is the private storage capability used by upload and ingestion.
type OriginalStorage interface {
	Check(context.Context) error
	Exists(context.Context, string) (bool, error)
	OpenOriginal(context.Context, string) (*Original, error)
	PutOriginal(context.Context, string, string, []byte) error
	Delete(context.Context, string) error
}

// Processor holds fixed rules and injected storage for ingestion.
type Processor struct {
	Engine            *Engine
	Originals         OriginalStorage
	MinimumCharacters int
	MinimumRatio      float64
}

func NewProcessor(settings Settings, originals OriginalStorage) (*Processor, error) {
	if settings.MinimumCharacters < 0 || settings.MinimumRatio < 0 || settings.MinimumRatio > 1 {
		return nil, Failure("SP_CONFIG_INVALID")
	}
	f, err := os.Open(settings.RulesPath)
	if err != nil {
		return nil, Failure("SP_RULES_LOAD_FAILED")
	}
	defer f.Close()
	engine, err := Load(f, settings.MatchTimeout, settings.DocumentBudget)
	if err != nil {
		return nil, err
	}
	return &Processor{Engine: engine, Originals: originals, MinimumCharacters: settings.MinimumCharacters, MinimumRatio: settings.MinimumRatio}, nil
}

func (p *Processor) Check(ctx context.Context) error {
	if p == nil || p.Engine == nil || p.Originals == nil {
		return Failure("SP_UNSUPPORTED_DEPLOYMENT")
	}
	return p.Originals.Check(ctx)
}

type sessionKey struct{}

// Session is private to one admitted linear pipeline execution. It is never
// reconstructed from API input, component output, cache or checkpoint data.
type Session struct {
	guard            outputGuard
	DatasetID        string
	OriginalLocation string
	Processor        *Processor
	DocumentID       string
	Round            string
	Name             string
	Result           Result
	JSONSourceResult *Result
	Parsed           bool
}

func WithSession(ctx context.Context, p *Processor, docID, round, name string) (context.Context, *Session, error) {
	if p == nil || p.Engine == nil || docID == "" || round == "" {
		return ctx, nil, Failure("SP_UNSUPPORTED_DEPLOYMENT")
	}
	ctx = p.Engine.WithBudget(ctx)
	if err := p.Engine.Scan(ctx, name); err != nil {
		return ctx, nil, err
	}
	s := &Session{Processor: p, DocumentID: docID, Round: round, Name: name}
	return context.WithValue(ctx, sessionKey{}, s), s, nil
}

func FromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey{}).(*Session)
	return s
}
