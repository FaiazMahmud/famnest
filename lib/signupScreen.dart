import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:testapp/validator.dart'; // Import the validators.dart file
import 'package:testapp/termsofServicesandPrivacyPolicy.dart';
import 'package:testapp/loginScreen.dart';

class signupScreen extends StatefulWidget {
  @override
  _SignupScreenState createState() => _SignupScreenState();
}

class _SignupScreenState extends State<signupScreen> {
  final _nameController = TextEditingController();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();

  bool _isChecked = false;

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
                "Create Your Account",
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Colors.teal[800],
                ),
              ),
              const SizedBox(height: 10),
              Text(
                "Join FamNest and manage your family's life in one place!",
                style: TextStyle(fontSize: 16, color: Colors.teal[600]),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 30),
              // Input Fields
              _buildTextField(
                controller: _nameController,
                label: "Name",
                icon: Icons.person,
              ),
              const SizedBox(height: 15),
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
              const SizedBox(height: 15),
              _buildTextField(
                controller: _confirmPasswordController,
                label: "Confirm Password",
                icon: Icons.lock,
                isPassword: true,
              ),
              const SizedBox(height: 20),
              // Terms and Conditions
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Checkbox(
                    value: _isChecked,
                    onChanged: (value) {
                      setState(() {
                        _isChecked = value!;
                      });
                    },
                  ),
                  Expanded(
                    child: RichText(
                      text: TextSpan(
                        text: "I have read and agree to the ",
                        style: TextStyle(color: Colors.teal[600], fontSize: 14),
                        children: [
                          TextSpan(
                            text: "Terms of Services",
                            style: TextStyle(
                              color: Colors.teal[800],
                              fontWeight: FontWeight.bold,
                              decoration: TextDecoration.underline,
                            ),
                            recognizer: TapGestureRecognizer()
                              ..onTap = () {
                                //Validators.showSnackBar(context, "Navigate to Terms of Services");
                                termsOfServicesAndPrivacyPolicy.showTermsOfServices(context);
                              },
                          ),
                          TextSpan(text: " and "),
                          TextSpan(
                            text: "Privacy Policy",
                            style: TextStyle(
                              color: Colors.teal[800],
                              fontWeight: FontWeight.bold,
                              decoration: TextDecoration.underline,
                            ),
                            recognizer: TapGestureRecognizer()
                              ..onTap = () {
                                //Validators.showSnackBar(context, "Navigate to Privacy Policy");
                                termsOfServicesAndPrivacyPolicy.showPrivacyPolicy(context);
                              },
                          ),
                          TextSpan(text: "."),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              // Sign-Up Button
              ElevatedButton(
                onPressed: () {
                  final nothavingName=Validators.validateFullName(_nameController.text);
                  final emailError = Validators.validateEmail(_emailController.text);
                  final passwordError = Validators.validatePassword(_passwordController.text);
                  final confirmPasswordError = Validators.validateConfirmPassword(
                    _passwordController.text,
                    _confirmPasswordController.text,
                  );

                  if(nothavingName!=null){
                    Validators.showSnackBar(context, nothavingName);
                    return;
                  }

                  if (emailError != null) {
                    Validators.showSnackBar(context, emailError);
                    return;
                  }

                  if (passwordError != null) {
                    Validators.showSnackBar(context, passwordError);
                    return;
                  }

                  if (confirmPasswordError != null) {
                    Validators.showSnackBar(context, confirmPasswordError);
                    return;
                  }

                  if (!_isChecked) {
                    Validators.showSnackBar(context, "You must agree to the Terms and Privacy Policy");
                    return;
                  }

                  // If all validations pass
                  Validators.showSnackBar(context, "Sign-Up Successful!", backgroundColor: Colors.green);
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.teal[700],
                  padding: const EdgeInsets.symmetric(horizontal: 50, vertical: 15),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(30),
                  ),
                ),
                child: const Text(
                  "Sign Up",
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white),
                ),
              ),
              const SizedBox(height: 20),
              // Already Have an Account
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    "Already have an account?",
                    style: TextStyle(fontSize: 16, color: Colors.teal[600]),
                  ),
                  TextButton(
                    onPressed: () {
                      // Navigate to Sign-In Page
                      Navigator.pushReplacement(
                        context,
                      MaterialPageRoute(builder: (context)=>loginScreen()),
                      );
                    },
                    child: Text(
                      "login",
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
      obscureText: isPassword,
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
      ),
    );
  }
}
