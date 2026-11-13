package dao

import (
	"context"
	"encoding/json"

	"ragflow/internal/entity"
	"ragflow/internal/sensitive"

	"gorm.io/gorm"
)

func readSecurityRecord(doc *entity.Document) (*sensitive.Record, error) {
	r := new(sensitive.Record)
	if len(doc.SecurityProcessingRecord) == 0 {
		return r, nil
	}
	b, err := json.Marshal(doc.SecurityProcessingRecord)
	if err != nil || json.Unmarshal(b, r) != nil {
		return nil, sensitive.Failure("SP_RESULT_SAVE_FAILED")
	}
	return r, nil
}

func saveSecurityRecord(ctx context.Context, tx *gorm.DB, docID string, r *sensitive.Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return sensitive.Failure("SP_RESULT_SAVE_FAILED")
	}
	var value entity.JSONMap
	if json.Unmarshal(b, &value) != nil {
		return sensitive.Failure("SP_RESULT_SAVE_FAILED")
	}
	res := tx.WithContext(ctx).Model(&entity.Document{}).Where("id = ? AND security_processing_enabled = ?", docID, true).Updates(map[string]any{
		"security_processing_record": value, "security_processed": r.Confirmed && r.FailureReason == "",
		"sensitive_replacement_count": r.Count(), "security_failure_reason": r.FailureReason,
	})
	if res.Error != nil {
		return sensitive.Failure("SP_RESULT_SAVE_FAILED")
	}
	return nil
}

// BeginSecurityRun is called inside the task/log binding transaction with an
// already locked document; it does not create an independent transaction.
func (d *DocumentDAO) BeginSecurityRun(ctx context.Context, tx *gorm.DB, doc *entity.Document, round string) error {
	if !doc.SecurityProcessingEnabled {
		return nil
	}
	r, err := readSecurityRecord(doc)
	if err != nil {
		return err
	}
	if err = r.Begin(round); err != nil {
		return err
	}
	return saveSecurityRecord(ctx, tx, doc.ID, r)
}

func (d *DocumentDAO) changeSecurityRecord(ctx context.Context, db *gorm.DB, id string, change func(*entity.Document, *sensitive.Record) error) error {
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		doc, err := d.GetByIDForUpdate(ctx, tx, id)
		if err != nil {
			return sensitive.Failure("SP_RESULT_SAVE_FAILED")
		}
		if !doc.SecurityProcessingEnabled {
			return sensitive.Failure("SP_CONFIG_INVALID")
		}
		r, err := readSecurityRecord(doc)
		if err != nil {
			return err
		}
		if err = change(doc, r); err != nil {
			return err
		}
		return saveSecurityRecord(ctx, tx, id, r)
	})
	if err != nil && sensitive.Reason(err) == "" {
		return sensitive.Failure("SP_RESULT_SAVE_FAILED")
	}
	return err
}

func (d *DocumentDAO) ConfirmSecurity(ctx context.Context, db *gorm.DB, id, round, version string, result sensitive.Result) error {
	return d.changeSecurityRecord(ctx, db, id, func(_ *entity.Document, r *sensitive.Record) error { return r.Confirm(round, version, result) })
}

func (d *DocumentDAO) FailSecurity(ctx context.Context, db *gorm.DB, id, round, reason string) error {
	return d.changeSecurityRecord(ctx, db, id, func(_ *entity.Document, r *sensitive.Record) error { return r.Fail(round, reason) })
}

// BeginManualSecurity checks the current document under its row lock. Only a
// source-less virtual document may obtain its first confirmation here.
func (d *DocumentDAO) BeginManualSecurity(ctx context.Context, db *gorm.DB, id, operation, version string, result sensitive.Result, allowEmpty bool) error {
	return d.changeSecurityRecord(ctx, db, id, func(doc *entity.Document, r *sensitive.Record) error {
		if !r.Confirmed {
			if !allowEmpty || doc.Type != "virtual" || (doc.Location != nil && *doc.Location != "") || r.FailureReason != "" || len(r.Pending) != 0 {
				return sensitive.Failure("SP_NOT_PROCESSED")
			}
			if err := r.Begin(operation); err != nil {
				return err
			}
			base := result
			base.Count = 0 // The successful write contributes its delta once below.
			if err := r.Confirm(operation, version, base); err != nil {
				return err
			}
		}
		return r.Register(operation, result.Count)
	})
}

func (d *DocumentDAO) FinishSecurityCount(ctx context.Context, db *gorm.DB, id, operation string, written bool) error {
	return d.changeSecurityRecord(ctx, db, id, func(_ *entity.Document, r *sensitive.Record) error { r.Finish(operation, written); return nil })
}
