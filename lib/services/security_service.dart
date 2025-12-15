import 'package:safe_device/safe_device.dart';

class SecurityService {
  
  /// Kiểm tra xem thiết bị có bị root 
  static Future<Map<String, dynamic>> checkDeviceSecurity() async {
    try {
      final isRooted = await SafeDevice.isJailBroken; 
      final isRealDevice = await SafeDevice.isRealDevice;
      final isDevelopmentMode = await SafeDevice.isDevelopmentModeEnable;
      
      return {
        'isSecure': !isRooted && !isDevelopmentMode && isRealDevice,
        'isRooted': isRooted, 
        'isDevelopmentMode': isDevelopmentMode,
        'isRealDevice': isRealDevice,
      };
    } catch (e) {
      print('Error checking device security: $e');
      // Nếu không check được, mặc định cho phép 
      return {
        'isSecure': true,
        'isRooted': false,
        'isDevelopmentMode': false,
        'isRealDevice': true,
        'error': e.toString(),
      };
    }
  }
}
