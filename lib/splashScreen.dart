import 'package:flutter/material.dart';
import 'dart:async';

class splashScreen extends StatefulWidget {
  @override
  _SplashScreenState createState() => _SplashScreenState();
}

class _SplashScreenState extends State<splashScreen> {
  @override
  void initState() {
    super.initState();
    // Navigate to the next screen after 3 seconds
    Timer(Duration(seconds: 3), () {
      Navigator.pushReplacementNamed(context, '/home'); // Replace '/home' with your main route
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.teal[50], // Background color for a soft look
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // App Logo
            ClipOval(
              child: Image.asset(
                'assets/authentications/famNestlogo.png', // Replace with the path to your logo image
                width: 120,
                height: 120,
                fit: BoxFit.cover,

              ),
            ),
            const SizedBox(height: 20),
            // App Name
            Text(
              "FamNest",
              style: TextStyle(
                fontSize: 36,
                fontWeight: FontWeight.bold,
                color: Colors.teal[800],
              ),
            ),
            const SizedBox(height: 10),
            // Tagline
            Text(
              "Your Family's Digital Hub",
              style: TextStyle(
                fontSize: 16,
                fontStyle: FontStyle.italic,
                color: Colors.teal[600],
              ),
            ),
            const SizedBox(height: 50),
            // Loading Indicator
            CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation<Color>(Colors.teal[700]!),
            ),
          ],
        ),
      ),
    );
  }
}
