---
authors: Vitor Enes (vitor@goteleport.com)
state: draft
---

# RFD 00XX - Tenant Data Reporting

## Required Approvals

* Engineering: @r0mant && @jimbishopp
* Product: @xinding33 || @klizhentas

## Table of Contents

* [What](#what)
* [Why](#why)
  * [Goals](#goals)
  * [Non\-Goals](#non-goals)
* [Details](#details)
  * [Open-source Teleport changes](#open-source-teleport-changes)
	* [`Client.StreamEvents` API](#clientstreamevents-api)
	* [`StreamEvents` RPC](#streamevents-rpc)
	* [`IAuditLog.StreamEvents` API](#iauditlogstreamevents-api)
	* [`dynamoevents.Log.StreamEvents` API](#dynamoeventslogstreamevents-api)
	  * [DynamoDB stream cursor](#dynamodb-stream-cursor)
	* [Retrieve Teleport user from Teleport event](#retrieve-teleport-user-from-teleport-event)
	* [Retrieve protocol from Teleport event](#retrieve-protocol-from-teleport-event)
  * [Teleport Enterprise changes](#teleport-enterprise-changes)
  * [Teleport Cloud changes](#teleport-cloud-changes)
* [Concerns and open questions](#concerns-and-open-questions)
* [Alternatives considered](#alternatives-considered)

## What

__TODO: update this to reflect latest changes__

This RFD proposes a way to extend Teleport so that the number of monthly active users (MAU) can be tracked.
In summary, this RFD proposes that:
- [Open-source Teleport](https://github.com/gravitational/teleport) is extended so that:
	- DynamoDB streams can be enabled for the event table
	- DynamoDB streams are leveraged to implement a new `StreamEvents` API
- [Teleport enterprise](https://github.com/gravitational/teleport.e) uses the new `StreamEvents` API to push (anonymized) Teleport events to a Sales Center gRPC service
- The gRPC service pushes the anonymized events to Amazon Timestream
- Sales Center queries Amazon Timestream in order to compute MAU and MAU-per protocol

## Why

The Cloud team wants to start tracking the number of monthly active users.
This is needed to help us understand the usage and growth of Teleport Cloud.

### Goals

* Push anonymized Teleport events to Amazon Timestream
* Compute MAU and MAU per-protocol using these events
* Have a pipeline that can be easily extended to support other kind of metrics in the future (e.g. time to first login, time to first resource, resource count, session time, etc...)

### Non-Goals
* Precisely define how the other metrics (besides MAU and MAU per-protocol) are to be tracked & computed

## Details

In this section we detail how [Open-source Teleport], [Teleport Enterprise] and [Teleport Cloud] can be extended to achieve our goals.

### Open-source Teleport changes

#### `Client.StreamEvents` API

The [Teleport client] will be extended with a new `StreamEvents` API similar to the `StreamSessionEvents` API added in [teleport#7360].

```go
func (c *Client) StreamEvents(ctx context.Context, cursor string) (chan events.StreamEvent, chan error)

func (c *Client) StreamSessionEvents(ctx context.Context, sessionID string, startIndex int64) (chan events.AuditEvent, chan error)
```

`StreamSessionEvents` returns a channel of `events.AuditEvent`s.
`StreamEvents` returns instead a channel of `events.StreamEvent`s that contain the same `events.AuditEvent` in addition to a stream `Cursor`.
This stream `Cursor` can be used to to resume streaming events by passing it as an argument to the `StreamEvents` API.

```go
type StreamEvent struct {
	// Event is an audit event.
	Event AuditEvent
	// Cursor is a stream cursor that can be used to resume the stream.
	Cursor string
}
```

#### `StreamEvents` RPC

These two APIs are build on top of server-streaming RPCs with the same name:

```protobuf
// StreamEventsRequest is a request to start or resume streaming audit events.
message StreamEventsRequest {
    // Cursor is an optional stream cursor that can be used to resume the stream.
    string Cursor = 1;
}

message StreamEvent {
	// Event is a typed gRPC formatted audit event.
	events.OneOf Event = 1;
	// Cursor is a stream cursor that can be used to resume the stream.
	string Cursor = 2;
}

service AuthService {
	// ...

	// StreamEvents streams audit events.
	rpc StreamEvents(StreamEventsRequest) returns (stream StreamEvent);
	// StreamSessionEvents streams audit events from a given session recording.
	rpc StreamSessionEvents(StreamSessionEventsRequest) returns (stream events.OneOf);

	// ...
}
```

Similarly to the Teleport API call, the `StreamSessionEvents` RPC returns a stream of `events.OneOf`s, while `StreamEvents` returns a stream of `StreamEvent`s that contain an `events.OneOf` and a stream `Cursor`.

#### `IAuditLog.StreamEvents` API

In order to implement the `StreamEvents` RPC, the `IAuditLog` interface will also be extended with a `StreamEvents` API (equal to the `Client.StreamEvents` being added):

```go
type IAuditLog interface {
	// ...

	StreamEvents(ctx context.Context, cursor string) (chan apievents.StreamEvent, chan error)

	StreamSessionEvents(ctx context.Context, sessionID session.ID, startIndex int64) (chan apievents.AuditEvent, chan error)

	// ...
}
```

#### `dynamoevents.Log.StreamEvents` API

`IAuditLog.StreamEvents` will only be implemented for [`dynamoevents.Log`].
For that, the existing streaming implementation in [`lib/backend/dynamo/shards.go`], which is used to watch for backend changes, will be generalized in order to support both needs.

In particular, this streaming implementation will have to support resuming the stream given some stream cursor.
This is currently not supported as, upon an error or a server restart, the backend starts streaming from the `LATEST` event in each active shard.

##### DynamoDB Stream cursor

Similarly to how [`dynamodb.Log.SearchEvents`] returns a [checkpoint key] that is JSON-encoded, a DynamoDB Stream cursor will be the following JSON-encoded struct:

```go
type streamCursor struct {
	// ShardIdToSequenceNumber is a mapping from a shard id to the latest sequence number
	// (from such shard) returned by the stream
	ShardIdToSequenceNumber map[string]string `json:"shard_id_to_sequence_number,omitempty"`
}
```

Next we give some information about DynamoDB streams, explaining why we have chosen such a representation for the stream cursor.
From the DynamoDB documentation:

> A stream consists of stream records.
> Each stream record is assigned a sequence number, reflecting the order in which the record was published to the stream.
> Stream records are organized into groups, or shards. 
> Shards are ephemeral: They are created and deleted automatically, as needed.
> Any shard can also split into multiple new shards; this also occurs automatically. (It's also possible for a parent shard to have just one child shard.)
> A shard might split in response to high levels of write activity on its parent table, so that applications can process records from multiple shards in parallel.
> Because shards have a lineage (parent and children), an application must always process a parent shard before it processes a child shard. This helps ensure that the stream records are also processed in the correct order.

When starting streaming, we can use [`DescribeStream`] to retrieve a list of active stream shards:

```json
"Shards": [
	{
		"ParentShardId": "string",
		"SequenceNumberRange": {
			"EndingSequenceNumber": "string",
			"StartingSequenceNumber": "string"
		},
		"ShardId": "string"
	}
],
```

> If the `SequenceNumberRange` has a `StartingSequenceNumber` but no `EndingSequenceNumber`, then the shard is still open (able to receive more stream records).
> If both `StartingSequenceNumber` and `EndingSequenceNumber` are present, then that shard is closed and can no longer receive more data.

For each of these shards, we also retrieve a shard iterator  using [`GetShardIterator`], providing the following information:

```json
{
   "SequenceNumber": "string",
   "ShardId": "string",
   "ShardIteratorType": "string",
   "StreamArn": "string"
}
```

We have the following `ShardIteratorType`s:

> - `AT_SEQUENCE_NUMBER` - Start reading exactly from the position denoted by a specific sequence number.
> - `AFTER_SEQUENCE_NUMBER` - Start reading right after the position denoted by a specific sequence number.
> - `TRIM_HORIZON` - Start reading at the last (untrimmed) stream record, which is the oldest record in the shard. In DynamoDB Streams, there is a 24 hour limit on data retention. Stream records whose age exceeds this limit are subject to removal (trimming) from the stream.
> - `LATEST` - Start reading just after the most recent stream record in the shard, so that you always read the most recent data in the shard.

Given a shard id `$ID` (returned by `DescribeStream`), if `streamCursor.ShardIdToSequenceNumber` contains `$ID`, then we set the `ShardIteratorType` to `AFTER_SEQUENCE_NUMBER` and `SequenceNumber` to `streamCursor.ShardIdToSequenceNumber[$ID]`.
Otherwise, we can either set it to `TRIM_HORIZON` or to `LATEST`.

Once we have a shard iterator returned by `GetShardIterator`, we can finally use it to [`GetRecords`] from the stream.

#### Retrieve Teleport user from Teleport event

In order to compute MAU, we need to extract from each Teleport event the Teleport user responsible for it.
With the exception of the events `AppSessionRequest`, `CertificateCreate`, `DesktopRecording`, `SessionPrint`, `SessionUpload` and `SessionConnect`, [all events] have a [`UserMetadata`] containing a `User` field:
```protobuf
// UserMetadata is a common user event metadata
message UserMetadata {
    // User is teleport user name
    string User = 1 [ (gogoproto.jsontag) = "user,omitempty" ];

    // ...
}
```

Note that any user that produces an event with `UserMetadata` is considered an active user.

For us to extract the user from the event, Teleport has to be extended with a `UserMetadataGetter` interface (similar e.g. to the [`SessionMetadataGetter`](https://github.com/gravitational/teleport/blob/8a27614b83590056e0d43394b926cf6db29b190b/lib/events/api.go#L577-L582)):
```go
// GetUser returns event user
func (m *UserMetadata) GetUser() string {
	return m.User
}

// UsersMetadataGetter represents interface
// that provides information about the user
type UserMetadataGetter interface {
	// GetUser returns the event user
	GetUser() string
}

// GetUser pulls the user from the events that have a UserMetadata.
// For other events an empty string is returned.
func GetUser(event events.AuditEvent) string {
	var user string

	if g, ok := event.(UserMetadataGetter); ok {
		user = g.GetUser()
	}

	return user
}
```

#### Retrieve protocol from Teleport event

In order to compute MAU per-protocol, 

__TODO__

This means that no Teleport changes are required for us to compute the protocol from a Teleport event.

### Teleport Enterprise changes

There's already a [usage reporter](https://github.com/gravitational/teleport.e/blob/21b2440ecd6ef64755785cc26a38658787b53ec7/lib/cloud/usagereporter/reporter.go) that periodically reports usage (counts of users, servers, databases, applications, kubernetes clusters, roles and auth connectors) to the Sales Center.

#### Anonymization

__TODO__

#### Filtering

__TODO__
```go
user := events.GetUser(event)
if user != "" {
	// PUSH
}
```

### Teleport Cloud changes

__TODO__

```protobuf
service TenantsService {
  // SubmitUsageReports reports usage
  rpc SubmitUsageReports(SubmitUsageReportsRequest) returns (EmptyResponse);
  // SubmitEvents reports anonymized audit events
  rpc SubmitEvents(SubmitEventsRequest) returns (EmptyResponse);

  // ...
}
```

## Concerns and open questions

__TODO__
- Is `UserMetadata.User` the correct identifier to be used?

## Alternatives considered

__TODO__


[Open-source Teleport]: https://github.com/gravitational/teleport
[Teleport Enterprise]: https://github.com/gravitational/teleport.e
[Teleport Cloud]: https://github.com/gravitational/cloud
[Teleport client]: https://github.com/gravitational/teleport/blob/cf205b01a5aa88fd4fcdb499ff9b9c40c4e5c335/api/client/client.go
[teleport#7360]: https://github.com/gravitational/teleport/pull/7360
[`dynamoevents.Log`]: https://github.com/gravitational/teleport/blob/cf205b01a5aa88fd4fcdb499ff9b9c40c4e5c335/lib/events/dynamoevents/dynamoevents.go
[`lib/backend/dynamo/shards.go`]: https://github.com/gravitational/teleport/blob/cf205b01a5aa88fd4fcdb499ff9b9c40c4e5c335/lib/backend/dynamo/shards.go
[`dynamodb.Log.SearchEvents`]: https://github.com/gravitational/teleport/blob/cf205b01a5aa88fd4fcdb499ff9b9c40c4e5c335/lib/events/dynamoevents/dynamoevents.go#L558-L560
[checkpoint key]: https://github.com/gravitational/teleport/blob/cf205b01a5aa88fd4fcdb499ff9b9c40c4e5c335/lib/events/dynamoevents/dynamoevents.go#L538-L548
[`DescribeStream`]: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_DescribeStream.html
[`GetShardIterator`]: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetShardIterator.html
[`GetRecords`]: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_GetRecords.html
[all events]: https://github.com/gravitational/teleport/blob/8a27614b83590056e0d43394b926cf6db29b190b/api/types/events/events.proto
[`UserMetadata`]: https://github.com/gravitational/teleport/blob/8a27614b83590056e0d43394b926cf6db29b190b/api/types/events/events.proto#L58-L61
