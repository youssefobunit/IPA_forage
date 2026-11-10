import 'package:supabase_flutter/supabase_flutter.dart';

/// A complete, transport-neutral representation of the workshop's local data.
typedef SyncSnapshot = Map<String, List<Map<String, Object?>>>;

abstract interface class CloudSyncClient {
  Future<void> upload(SyncSnapshot snapshot);
  Future<SyncSnapshot?> download();
}

/// Stores the workshop snapshot in Supabase. Authentication and row-level
/// security are enforced by the database; this client never uses a service
/// role key in the mobile application.
class SupabaseCloudSyncClient implements CloudSyncClient {
  SupabaseCloudSyncClient(this._client);

  final SupabaseClient _client;
  static const _table = 'workshop_snapshots';
  static const _workspaceId = 'main';

  @override
  Future<void> upload(SyncSnapshot snapshot) async {
    await _client.from(_table).upsert({
      'id': _workspaceId,
      'snapshot': snapshot,
      'updated_at': DateTime.now().toUtc().toIso8601String(),
    });
  }

  @override
  Future<SyncSnapshot?> download() async {
    final row = await _client
        .from(_table)
        .select('snapshot')
        .eq('id', _workspaceId)
        .maybeSingle();
    if (row == null || row['snapshot'] is! Map) return null;

    final result = <String, List<Map<String, Object?>>>{};
    for (final entry in (row['snapshot'] as Map).entries) {
      if (entry.value is! List) {
        throw const FormatException(
          'La synchronisation distante est invalide.',
        );
      }
      result[entry.key.toString()] = (entry.value as List).map((rawRow) {
        if (rawRow is! Map) {
          throw const FormatException(
            'La synchronisation distante est invalide.',
          );
        }
        return Map<String, Object?>.fromEntries(
          rawRow.entries.map(
            (field) => MapEntry(field.key.toString(), field.value),
          ),
        );
      }).toList();
    }
    return result;
  }
}
