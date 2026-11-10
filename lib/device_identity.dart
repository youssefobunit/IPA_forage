import 'dart:convert';
import 'dart:math';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// An app-scoped, randomly generated device identifier stored in Android's
/// encrypted storage or Apple's Keychain. It is not a hardware serial number:
/// modern Android and iOS intentionally do not expose a reliable hardware ID
/// to ordinary apps. Removing the app clears this identifier and therefore
/// correctly requires a new administrator approval.
class DeviceIdentity {
  const DeviceIdentity({required this.id, required this.label});

  final String id;
  final String label;

  static const _storage = FlutterSecureStorage();
  static const _storageKey = 'forage.trusted_device_id.v1';

  static Future<DeviceIdentity> load() async {
    var id = await _storage.read(key: _storageKey);
    if (id == null || id.isEmpty) {
      id = base64UrlEncode(
        List<int>.generate(32, (_) => Random.secure().nextInt(256)),
      ).replaceAll('=', '');
      await _storage.write(key: _storageKey, value: id);
    }
    return DeviceIdentity(id: id, label: await _label());
  }

  static Future<String> _label() async {
    final info = DeviceInfoPlugin();
    try {
      final android = await info.androidInfo;
      final brand = android.brand.trim();
      final model = android.model.trim();
      return [brand, model].where((value) => value.isNotEmpty).join(' ');
    } catch (_) {
      try {
        final ios = await info.iosInfo;
        return ios.model.trim().isEmpty ? 'iPhone / iPad' : ios.model.trim();
      } catch (_) {
        return 'Appareil inconnu';
      }
    }
  }
}
