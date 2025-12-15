import 'package:flutter/material.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:image_picker/image_picker.dart';
import 'dart:io';
import 'package:lnmq/models/user_model.dart';
import 'package:lnmq/services/auth_service.dart';
import 'package:lnmq/services/user_service.dart';
import 'package:lnmq/services/storage_service.dart';
import 'package:lnmq/screens/user_invoice_screen.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  final AuthService _authService = AuthService();
  final UserService _userService = UserService();
  final StorageService _storageService = StorageService();

  // Controllers cho các trường thông tin
  late TextEditingController _displayNameController;
  late TextEditingController _phoneController;
  late TextEditingController _otpController;
  late TextEditingController _addressController;
  late TextEditingController _birthdateController;
  late TextEditingController _emergencyContactController;
  late TextEditingController _emergencyPhoneController;
  late TextEditingController _nationalIdController;
  late TextEditingController _occupationController;
  
  File? _pickedImage;
  bool _isLoading = false;
  bool _otpSent = false;
  bool _otpVerified = false;
  bool _isSendingOTP = false;
  String _selectedGender = 'Khác';
  DateTime? _selectedBirthdate;

  final List<String> _genders = ['Nam', 'Nữ', 'Khác'];
  final List<String> _travelPreferences = [
    'Du lịch biển',
    'Du lịch núi',
    'Du lịch văn hóa',
    'Du lịch ẩm thực',
    'Du lịch phiêu lưu',
    'Du lịch nghỉ dưỡng',
    'Du lịch lịch sử',
    'Du lịch tâm linh'
  ];
  List<String> _selectedPreferences = [];

  @override
  void initState() {
    super.initState();
    _displayNameController = TextEditingController();
    _phoneController = TextEditingController();
    _otpController = TextEditingController();
    _addressController = TextEditingController();
    _birthdateController = TextEditingController();
    _emergencyContactController = TextEditingController();
    _emergencyPhoneController = TextEditingController();
    _nationalIdController = TextEditingController();
    _occupationController = TextEditingController();
    _loadUserProfile();
  }

  Future<void> _loadUserProfile() async {
    User? currentUser = _authService.getCurrentUser();
    if (currentUser != null) {
      _userService.getUserData(currentUser.uid).listen((appUser) {
        if (appUser != null && mounted) {
          _displayNameController.text = appUser.displayName ?? currentUser.displayName ?? '';
          _phoneController.text = appUser.phoneNumber ?? '';
          _addressController.text = appUser.address ?? '';
          _emergencyContactController.text = appUser.emergencyContactName ?? '';
          _emergencyPhoneController.text = appUser.emergencyContactPhone ?? '';
          _nationalIdController.text = appUser.nationalId ?? '';
          _occupationController.text = appUser.occupation ?? '';
          
          if (appUser.birthdate != null) {
            _selectedBirthdate = appUser.birthdate;
            _birthdateController.text = '${_selectedBirthdate!.day}/${_selectedBirthdate!.month}/${_selectedBirthdate!.year}';
          }
          
          _selectedGender = appUser.gender ?? 'Khác';
          _selectedPreferences = appUser.travelPreferences ?? [];
          
          // Check if phone number is already verified in Firebase Auth
          if (currentUser.phoneNumber != null && currentUser.phoneNumber!.isNotEmpty) {
            // Format Firebase phone number to match input (+84xxx → 0xxx)
            String firebasePhone = currentUser.phoneNumber!;
            String localPhone = _phoneController.text.trim();
            
            // Convert Firebase phone (+84974585626) to local format (0974585626)
            if (firebasePhone.startsWith('+84') && localPhone.startsWith('0')) {
              String firebasePhoneLocal = '0${firebasePhone.substring(3)}';
              if (firebasePhoneLocal == localPhone) {
                _otpVerified = true; // Phone already verified in Firebase
              }
            }
          }
          
          setState(() {});
        }
      });
    }
  }

  Future<void> _selectBirthdate() async {
    final DateTime? picked = await showDatePicker(
      context: context,
      initialDate: _selectedBirthdate ?? DateTime(1990),
      firstDate: DateTime(1920),
      lastDate: DateTime.now(),
    );
    if (picked != null && picked != _selectedBirthdate) {
      setState(() {
        _selectedBirthdate = picked;
        _birthdateController.text = '${picked.day}/${picked.month}/${picked.year}';
      });
    }
  }

  Future<void> _pickImage() async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(source: ImageSource.gallery, imageQuality: 75);

    if (pickedFile != null) {
      setState(() {
        _pickedImage = File(pickedFile.path);
      });
    }
  }

  Future<void> _sendOTP() async {
    final phone = _phoneController.text.trim();
    
    if (phone.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Vui lòng nhập số điện thoại')),
      );
      return;
    }
    
    // Validate phone format
    if (!RegExp(r'^0[0-9]{9}$').hasMatch(phone)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Số điện thoại không hợp lệ (10 số, bắt đầu bằng 0)')),
      );
      return;
    }

    setState(() => _isSendingOTP = true);

    await _authService.sendOTP(
      phone,
      onCodeSent: (message) {
        setState(() {
          _otpSent = true;
          _isSendingOTP = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(message)),
        );
      },
      onError: (error) {
        setState(() => _isSendingOTP = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(error), backgroundColor: Colors.red),
        );
      },
      onAutoVerified: () {
        setState(() {
          _otpSent = true;
          _otpVerified = true;
          _isSendingOTP = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Số điện thoại đã được xác thực tự động!'), backgroundColor: Colors.green),
        );
      },
    );
  }

  Future<void> _verifyOTP() async {
    final otp = _otpController.text.trim();
    
    if (otp.isEmpty || otp.length != 6) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Vui lòng nhập mã OTP 6 số')),
      );
      return;
    }

    setState(() => _isLoading = true);

    try {
      final success = await _authService.verifyOTP(otp);
      if (success) {
        setState(() => _otpVerified = true);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Xác thực OTP thành công!'), backgroundColor: Colors.green),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString()), backgroundColor: Colors.red),
        );
      }
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _updateProfile() async {
    // Kiểm tra OTP nếu có số điện thoại
    final phone = _phoneController.text.trim();
    if (phone.isNotEmpty && !_otpVerified) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Vui lòng xác thực OTP trước khi cập nhật hồ sơ'),
          backgroundColor: Colors.orange,
        ),
      );
      return;
    }

    setState(() {
      _isLoading = true;
    });

    try {
      String? newPhotoUrl;
      if (_pickedImage != null) {
        newPhotoUrl = await _storageService.uploadImage(
          _pickedImage!,
          'profile_pictures/${_authService.getCurrentUser()!.uid}',
        );
      }

      // Cập nhật Firebase Auth profile
      await _authService.updateUserProfile(
        displayName: _displayNameController.text.trim(),
        photoUrl: newPhotoUrl,
      );

      // Cập nhật Firestore user document với thông tin chi tiết
      await _userService.updateUserProfile(
        displayName: _displayNameController.text.trim(),
        phoneNumber: phone,
        address: _addressController.text.trim(),
        birthdate: _selectedBirthdate,
        gender: _selectedGender,
        emergencyContactName: _emergencyContactController.text.trim(),
        emergencyContactPhone: _emergencyPhoneController.text.trim(),
        nationalId: _nationalIdController.text.trim(),
        occupation: _occupationController.text.trim(),
        travelPreferences: _selectedPreferences,
        photoUrl: newPhotoUrl,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Cập nhật hồ sơ thành công!')),
        );
        // Reset OTP state after successful update
        setState(() {
          _otpSent = false;
          _otpVerified = false;
          _otpController.clear();
        });
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Lỗi khi cập nhật hồ sơ: ${e.toString()}')),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  void dispose() {
    _displayNameController.dispose();
    _phoneController.dispose();
    _otpController.dispose();
    _addressController.dispose();
    _birthdateController.dispose();
    _emergencyContactController.dispose();
    _emergencyPhoneController.dispose();
    _nationalIdController.dispose();
    _occupationController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    User? currentUser = _authService.getCurrentUser();

    return StreamBuilder<AppUser?>(
      stream: currentUser != null ? _userService.getUserData(currentUser.uid) : null,
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting && !_isLoading) {
          return const Scaffold(
            body: Center(child: CircularProgressIndicator()),
          );
        }

        AppUser? appUser = snapshot.data;
        String? currentPhotoUrl = currentUser?.photoURL ?? appUser?.photoUrl;

        return Scaffold(
          appBar: AppBar(
            title: const Text('Hồ sơ cá nhân', style: TextStyle(color: Colors.black87)),
            backgroundColor: Colors.transparent,
            elevation: 0,
            actions: [
              TextButton.icon(
                onPressed: () async {
                  await _authService.signOut();
                  if (mounted) {
                    Navigator.of(context).pushNamedAndRemoveUntil('/auth', (route) => false);
                  }
                },
                icon: const Icon(Icons.logout, color: Colors.redAccent),
                label: const Text(
                  'Đăng xuất',
                  style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.w500),
                ),
              ),
            ],
          ),
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Avatar section
                Center(
                  child: Stack(
                    children: [
                      CircleAvatar(
                        radius: 60,
                        backgroundColor: Colors.blueGrey[100],
                        backgroundImage: _pickedImage != null
                            ? FileImage(_pickedImage!) as ImageProvider<Object>
                            : (currentPhotoUrl != null ? NetworkImage(currentPhotoUrl) : null),
                        child: _pickedImage == null && currentPhotoUrl == null
                            ? const Icon(Icons.person, size: 60, color: Colors.blueGrey)
                            : null,
                      ),
                      Positioned(
                        bottom: 0,
                        right: 0,
                        child: IconButton(
                          icon: const Icon(Icons.camera_alt, color: Colors.blueAccent),
                          onPressed: _pickImage,
                          style: IconButton.styleFrom(
                            backgroundColor: Colors.white,
                            shape: const CircleBorder(),
                            side: BorderSide(color: Colors.grey[300]!),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 32),

                // Thông tin cơ bản
                const Text(
                  'Thông tin cơ bản',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 16),
                
                TextField(
                  controller: _displayNameController,
                  decoration: InputDecoration(
                    labelText: 'Tên hiển thị *',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.person),
                  ),
                ),
                const SizedBox(height: 16),

                // Phone number with OTP verification
                Row(
                  children: [
                    Expanded(
                      flex: 3,
                      child: TextField(
                        controller: _phoneController,
                        keyboardType: TextInputType.phone,
                        decoration: InputDecoration(
                          labelText: 'Số điện thoại *',
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                          prefixIcon: const Icon(Icons.phone),
                          hintText: '0901234567',
                          suffixIcon: _otpVerified
                              ? const Icon(Icons.verified, color: Colors.green)
                              : null,
                          helperText: _otpVerified ? 'Đã xác thực' : 'Cần xác thực OTP',
                          helperStyle: TextStyle(
                            color: _otpVerified ? Colors.green : Colors.orange,
                            fontSize: 11,
                          ),
                        ),
                        onChanged: (value) {
                          // Reset OTP state when phone changes
                          if (_otpSent || _otpVerified) {
                            setState(() {
                              _otpSent = false;
                              _otpVerified = false;
                              _otpController.clear();
                            });
                          }
                        },
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      flex: 1,
                      child: ElevatedButton(
                        onPressed: (_isSendingOTP || _otpVerified) ? null : _sendOTP,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _otpVerified ? Colors.green : Colors.blueAccent,
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                        ),
                        child: _isSendingOTP
                            ? const SizedBox(
                                height: 16,
                                width: 16,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Colors.white,
                                ),
                              )
                            : Text(
                                _otpVerified ? 'Đã xác thực' : (_otpSent ? 'Gửi lại' : 'Gửi OTP'),
                                style: const TextStyle(fontSize: 12),
                                textAlign: TextAlign.center,
                              ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                
                // OTP input field (show only after OTP sent)
                if (_otpSent && !_otpVerified) ...[
                  Row(
                    children: [
                      Expanded(
                        flex: 3,
                        child: TextField(
                          controller: _otpController,
                          keyboardType: TextInputType.number,
                          maxLength: 6,
                          decoration: InputDecoration(
                            labelText: 'Nhập mã OTP',
                            border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                            prefixIcon: const Icon(Icons.security),
                            hintText: '123456',
                            counterText: '',
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        flex: 1,
                        child: ElevatedButton(
                          onPressed: _isLoading ? null : _verifyOTP,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.green,
                            padding: const EdgeInsets.symmetric(vertical: 16),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(10),
                            ),
                          ),
                          child: _isLoading
                              ? const SizedBox(
                                  height: 16,
                                  width: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Colors.white,
                                  ),
                                )
                              : const Text(
                                  'Xác thực',
                                  style: TextStyle(fontSize: 12),
                                  textAlign: TextAlign.center,
                                ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    '⚠️ Nhập mã OTP 6 số đã được gửi đến số điện thoại của bạn',
                    style: TextStyle(fontSize: 12, color: Colors.orange, fontStyle: FontStyle.italic),
                  ),
                  const SizedBox(height: 16),
                ],
                
                if (_otpVerified) ...[
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.green.shade50,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: Colors.green.shade200),
                    ),
                    child: const Row(
                      children: [
                        Icon(Icons.check_circle, color: Colors.green),
                        SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Số điện thoại đã được xác thực thành công!',
                            style: TextStyle(color: Colors.green, fontWeight: FontWeight.w500),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),
                ],

                TextField(
                  controller: _addressController,
                  decoration: InputDecoration(
                    labelText: 'Địa chỉ *',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.location_on),
                    hintText: 'Số nhà, đường, quận/huyện, tỉnh/thành phố',
                  ),
                  maxLines: 2,
                ),
                const SizedBox(height: 16),

                // Ngày sinh và giới tính
                Row(
                  children: [
                    Expanded(
                      child: TextField(
                        controller: _birthdateController,
                        readOnly: true,
                        onTap: _selectBirthdate,
                        decoration: InputDecoration(
                          labelText: 'Ngày sinh',
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                          prefixIcon: const Icon(Icons.calendar_today),
                          hintText: 'DD/MM/YYYY',
                        ),
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: DropdownButtonFormField<String>(
                        value: _selectedGender,
                        decoration: InputDecoration(
                          labelText: 'Giới tính',
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                          prefixIcon: const Icon(Icons.people),
                        ),
                        items: _genders.map((gender) {
                          return DropdownMenuItem(value: gender, child: Text(gender));
                        }).toList(),
                        onChanged: (value) {
                          setState(() {
                            _selectedGender = value!;
                          });
                        },
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _occupationController,
                  decoration: InputDecoration(
                    labelText: 'Nghề nghiệp',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.work),
                    hintText: 'Sinh viên, Nhân viên văn phòng, Giáo viên...',
                  ),
                ),
                const SizedBox(height: 24),

                // Thông tin liên hệ khẩn cấp
                const Text(
                  'Liên hệ khẩn cấp',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _emergencyContactController,
                  decoration: InputDecoration(
                    labelText: 'Tên người liên hệ khẩn cấp',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.contact_emergency),
                    hintText: 'Họ tên người thân',
                  ),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _emergencyPhoneController,
                  keyboardType: TextInputType.phone,
                  decoration: InputDecoration(
                    labelText: 'Số điện thoại khẩn cấp',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.phone_in_talk),
                    hintText: '0901234567',
                  ),
                ),
                const SizedBox(height: 24),

                // Thông tin bổ sung
                const Text(
                  'Thông tin bổ sung',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 16),

                TextField(
                  controller: _nationalIdController,
                  decoration: InputDecoration(
                    labelText: 'Số CCCD/CMND',
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                    prefixIcon: const Icon(Icons.badge),
                    hintText: '123456789012',
                  ),
                ),
                const SizedBox(height: 16),

                // Sở thích du lịch
                const Text(
                  'Sở thích du lịch',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: _travelPreferences.map((preference) {
                    final isSelected = _selectedPreferences.contains(preference);
                    return FilterChip(
                      label: Text(preference),
                      selected: isSelected,
                      onSelected: (selected) {
                        setState(() {
                          if (selected) {
                            _selectedPreferences.add(preference);
                          } else {
                            _selectedPreferences.remove(preference);
                          }
                        });
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: 32),

                // Nút cập nhật
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _isLoading ? null : _updateProfile,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blueAccent,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    child: _isLoading
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(
                              color: Colors.white,
                              strokeWidth: 3,
                            ),
                          )
                        : const Text('Cập nhật hồ sơ', style: TextStyle(fontSize: 16)),
                  ),
                ),
                const SizedBox(height: 16),
                
                // Nút xem hóa đơn
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (context) => const UserInvoiceScreen()),
                      );
                    },
                    icon: const Icon(Icons.receipt_long),
                    label: const Text('Xem hóa đơn của tôi'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.green,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                
                const Text(
                  '* Thông tin bắt buộc\n'
                  'Thông tin này sẽ giúp chúng tôi hỗ trợ bạn tốt hơn trong quá trình du lịch.',
                  style: TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}