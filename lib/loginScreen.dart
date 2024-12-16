//import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:testapp/createOrJoinGroup.dart';
import 'package:testapp/validator.dart'; // Import the validators.dart file
import 'package:testapp/signupScreen.dart'; // Assuming this is where your Sign Up page is located

class loginScreen extends StatefulWidget {
  @override
  _LoginScreenState createState() => _LoginScreenState();
}

class _LoginScreenState extends State<loginScreen> {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();

  bool _isPasswordVisible = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.teal[50],
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              const SizedBox(height: 50),
              // Circular Image Decoration
              ClipOval(
                child: SizedBox(
                  width: 150,
                  height: 150,
                  child: Image.asset(
                    'assets/authentications/test.png', // Replace with your SVG or image path
                    fit: BoxFit.cover,
                  ),
                ),
              ),
              const SizedBox(height: 20),
              // Page Title
              Text(
                "Welcome Back",
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Colors.teal[800],
                ),
              ),
              const SizedBox(height: 10),
              Text(
                "Log in to your FamNest account.",
                style: TextStyle(fontSize: 16, color: Colors.teal[600]),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 30),
              // Input Fields
              _buildTextField(
                controller: _emailController,
                label: "Email",
                icon: Icons.email,
              ),
              const SizedBox(height: 15),
              _buildTextField(
                controller: _passwordController,
                label: "Password",
                icon: Icons.lock,
                isPassword: true,
              ),
              const SizedBox(height: 20),
              // Forget Password
              Align(
                alignment: Alignment.centerRight,
                child: TextButton(
                  onPressed: () {
                    // Handle forget password action
                    print("Navigate to Forget Password");
                  },
                  child: Text(
                    "Forgot Password?",
                    style: TextStyle(
                      fontSize: 14,
                      color: Colors.teal[700],
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 20),
              // Login Button
              ElevatedButton(
                onPressed: () {
                  final emailError = Validators.validateEmail(_emailController.text);
                  final passwordError = Validators.validatePassword(_passwordController.text);

                  if (emailError != null) {
                    Validators.showSnackBar(context, emailError);
                    return;
                  }

                  if (passwordError != null) {
                    Validators.showSnackBar(context, passwordError);
                    return;
                  }

                  // If all validations pass
                  Validators.showSnackBar(context, "Login Successful!", backgroundColor: Colors.green);
                  Navigator.pushReplacement(context,
                      MaterialPageRoute(builder: (context)=>createOrJoinGroup()),);
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.teal[700],
                  padding: const EdgeInsets.symmetric(horizontal: 50, vertical: 15),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(30),
                  ),
                ),
                child: const Text(
                  "Login",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white),
                ),
              ),
              const SizedBox(height: 20),
              // No Account - Navigate to Sign Up Page
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    "Don't have an account?",
                    style: TextStyle(fontSize: 16, color: Colors.teal[600]),
                  ),
                  TextButton(
                    onPressed: () {
                      // Navigate to Sign Up Page
                      Navigator.pushReplacement(
                        context,
                        MaterialPageRoute(builder: (context) => signupScreen()),
                      );
                    },
                    child: Text(
                      "Sign Up",
                      style: TextStyle(fontSize: 16, color: Colors.teal[700], fontWeight: FontWeight.bold),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  // Helper Widget for Text Fields
  Widget _buildTextField({
    required TextEditingController controller,
    required String label,
    required IconData icon,
    bool isPassword = false,
  }) {
    return TextField(
      controller: controller,
      obscureText: isPassword ? !_isPasswordVisible : false,
      decoration: InputDecoration(
        prefixIcon: Icon(icon, color: Colors.teal),
        labelText: label,
        labelStyle: TextStyle(color: Colors.teal[600]),
        filled: true,
        fillColor: Colors.white,
        focusedBorder: OutlineInputBorder(
          borderSide: BorderSide(color: Colors.teal[700]!),
          borderRadius: BorderRadius.circular(10),
        ),
        enabledBorder: OutlineInputBorder(
          borderSide: BorderSide(color: Colors.teal[300]!),
          borderRadius: BorderRadius.circular(10),
        ),
        suffixIcon: isPassword
            ? IconButton(
          icon: Icon(
            _isPasswordVisible ? Icons.visibility_off : Icons.visibility,
            color: Colors.teal,
          ),
          onPressed: () {
            setState(() {
              _isPasswordVisible = !_isPasswordVisible;
            });
          },
        )
            : null,
      ),
    );
  }
}
