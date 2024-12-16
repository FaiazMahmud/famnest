import 'package:flutter/material.dart';

class Validators {

  static String? validateFullName(String? Name){
    if(Name==null || Name.isEmpty){
      return 'Name is required';
    }
    return null;
  }

  // Email Validation
  static String? validateEmail(String? email) {
    if (email == null || email.isEmpty) {
      return 'Email is required';
    }
    final emailRegex = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$');
    if (!emailRegex.hasMatch(email)) {
      return 'Enter a valid email';
    }
    return null;
  }

  // Password Validation
  static String? validatePassword(String? password) {
    if (password == null || password.isEmpty) {
      return 'Password is required';
    }
    if (password.length < 8) {
      return 'Password must be at least 8 characters';
    }
    final hasUpperCase = password.contains(RegExp(r'[A-Z]'));
    final hasLowerCase = password.contains(RegExp(r'[a-z]'));
    final hasNumber = password.contains(RegExp(r'\d'));
    if (!hasUpperCase || !hasLowerCase || !hasNumber) {
      return 'Password must include uppercase, lowercase, and a number';
    }
    return null;
  }

  // Confirm Password Validation
  static String? validateConfirmPassword(String? password, String? confirmPassword) {
    if (confirmPassword == null || confirmPassword.isEmpty) {
      return 'Please confirm your password';
    }
    if (password != confirmPassword) {
      return 'Passwords do not match';
    }
    return null;
  }

  // SnackBar Helper
  static void showSnackBar(BuildContext context, String message, {Color? backgroundColor}) {
    final snackBar = SnackBar(
      content: Text(message),
      backgroundColor: backgroundColor ?? Colors.red,
      behavior: SnackBarBehavior.floating,
    );
    ScaffoldMessenger.of(context).showSnackBar(snackBar);
  }
}
