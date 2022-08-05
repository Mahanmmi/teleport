// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sqlbk

import (
	"context"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"
)

func (b *Backend) AuditLog() events.IAuditLog {
	return AuditLog{b}
}

type AuditLog struct {
	b *Backend
}

// Close does nothing, as AuditLog is merely using the DB from a Backend.
func (AuditLog) Close() error { return nil }

// GetSessionChunk returns NotImplemented because this is an external audit log
// that only deals in events.
func (AuditLog) GetSessionChunk(namespace string, sid session.ID, offsetBytes int, maxBytes int) ([]byte, error) {
	return nil, trace.NotImplemented("GetSessionChunk not implemented for sqlbk.AuditLog")
}

// StreamSessionEvents returns NotImplemented because this is an external audit
// log that only deals in events.
func (AuditLog) StreamSessionEvents(ctx context.Context, sessionID session.ID, startIndex int64) (chan apievents.AuditEvent, chan error) {
	errCh := make(chan error, 1)
	errCh <- trace.NotImplemented("StreamSessionEvents not implemented for sqlbk.AuditLog")
	return nil, errCh
}

// EmitAuditEvent implements events.IAuditLog
func (a AuditLog) EmitAuditEvent(ctx context.Context, event apievents.AuditEvent) error {
	return a.b.retryTx(ctx, a.b.db.Begin, func(tx Tx) error {
		return nil
	})
}

// GetSessionEvents implements events.IAuditLog
func (AuditLog) GetSessionEvents(namespace string, sid session.ID, after int, includePrintEvents bool) ([]events.EventFields, error) {
	return nil, trace.NotImplemented("temporary")
}

// SearchEvents implements events.IAuditLog
func (AuditLog) SearchEvents(fromUTC time.Time, toUTC time.Time, namespace string, eventTypes []string, limit int, order types.EventOrder, startKey string) ([]apievents.AuditEvent, string, error) {
	return nil, "", trace.NotImplemented("temporary")
}

// SearchSessionEvents implements events.IAuditLog
func (AuditLog) SearchSessionEvents(fromUTC time.Time, toUTC time.Time, limit int, order types.EventOrder, startKey string, cond *types.WhereExpr, sessionID string) ([]apievents.AuditEvent, string, error) {
	return nil, "", trace.NotImplemented("temporary")
}

// var _ events.IAuditLog = (*Backend)(nil)

// type IAuditLog interface {
// 	// Closer releases connection and resources associated with log if any
// 	io.Closer

// 	// EmitAuditEvent emits audit event
// 	EmitAuditEvent(context.Context, apievents.AuditEvent) error

// 	// GetSessionChunk returns a reader which can be used to read a byte stream
// 	// of a recorded session starting from 'offsetBytes' (pass 0 to start from the
// 	// beginning) up to maxBytes bytes.
// 	//
// 	// If maxBytes > MaxChunkBytes, it gets rounded down to MaxChunkBytes
// 	GetSessionChunk(namespace string, sid session.ID, offsetBytes, maxBytes int) ([]byte, error)

// 	// Returns all events that happen during a session sorted by time
// 	// (oldest first).
// 	//
// 	// after tells to use only return events after a specified cursor Id
// 	//
// 	// This function is usually used in conjunction with GetSessionReader to
// 	// replay recorded session streams.
// 	GetSessionEvents(namespace string, sid session.ID, after int, includePrintEvents bool) ([]EventFields, error)

// 	// SearchEvents is a flexible way to find events.
// 	//
// 	// Event types to filter can be specified and pagination is handled by an iterator key that allows
// 	// a query to be resumed.
// 	//
// 	// The only mandatory requirement is a date range (UTC).
// 	//
// 	// This function may never return more than 1 MiB of event data.
// 	SearchEvents(fromUTC, toUTC time.Time, namespace string, eventTypes []string, limit int, order types.EventOrder, startKey string) ([]apievents.AuditEvent, string, error)

// 	// SearchSessionEvents is a flexible way to find session events.
// 	// Only session.end events are returned by this function.
// 	// This is used to find completed sessions.
// 	//
// 	// Event types to filter can be specified and pagination is handled by an iterator key that allows
// 	// a query to be resumed.
// 	//
// 	// This function may never return more than 1 MiB of event data.
// 	SearchSessionEvents(fromUTC, toUTC time.Time, limit int, order types.EventOrder, startKey string, cond *types.WhereExpr, sessionID string) ([]apievents.AuditEvent, string, error)

// 	// StreamSessionEvents streams all events from a given session recording. An error is returned on the first
// 	// channel if one is encountered. Otherwise the event channel is closed when the stream ends.
// 	// The event channel is not closed on error to prevent race conditions in downstream select statements.
// 	StreamSessionEvents(ctx context.Context, sessionID session.ID, startIndex int64) (chan apievents.AuditEvent, chan error)
// }
