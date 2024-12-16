import 'package:flutter/material.dart';
import 'package:testapp/loginScreen.dart';
import 'package:testapp/mainHomepage.dart';

class createOrJoinGroup extends StatefulWidget {
  @override
  _CreateOrJoinGroupState createState() => _CreateOrJoinGroupState();
}

class _CreateOrJoinGroupState extends State<createOrJoinGroup> {
  final _groupNameController = TextEditingController();
  final _groupCodeController = TextEditingController();

  bool _isJoiningGroup = false;

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
              // Banner Section
              Container(
                width: double.infinity,
                height: 200,
                decoration: BoxDecoration(
                  color: Colors.teal[300],
                  borderRadius: BorderRadius.circular(15),
                  image: DecorationImage(
                    image: AssetImage('assets/authentications/banner.png'), // Replace with your banner image
                    fit: BoxFit.cover,
                  ),
                ),
              ),
              const SizedBox(height: 30),
              // Heading
              Text(
                "Create or Join a Group",
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Colors.teal[800],
                ),
              ),
              const SizedBox(height: 15),
              // Group Name Input Field
              if (!_isJoiningGroup)
                Column(
                  children: [
                    _buildTextField(
                      controller: _groupNameController,
                      label: "Group Name",
                      icon: Icons.group,
                    ),
                    const SizedBox(height: 15),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          "Have a code?",
                          style: TextStyle(
                            fontSize: 16,
                            color: Colors.teal[600],
                          ),
                        ),
                        TextButton(
                          onPressed: () {
                            setState(() {
                              _isJoiningGroup = true;
                            });
                          },
                          child: Text(
                            "Join Group",
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              color: Colors.teal[700],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              if (_isJoiningGroup) ...[
                Text(
                  "Enter Group Code",
                  style: TextStyle(
                    fontSize: 18,
                    color: Colors.teal[800],
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 10),
                _buildTextField(
                  controller: _groupCodeController,
                  label: "Group Code",
                  icon: Icons.vpn_key,
                ),
                const SizedBox(height: 15),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text(
                      "Want to create a new group?",
                      style: TextStyle(fontSize: 16, color: Colors.teal[600]),
                    ),
                    TextButton(
                      onPressed: () {
                        setState(() {
                          _isJoiningGroup = false;
                        });
                      },
                      child: Text(
                        "Create Group",
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Colors.teal[700],
                        ),
                      ),
                    ),
                  ],
                ),
              ],
              const SizedBox(height: 30),
              // Cancel and Done Buttons
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  // Cancel Button
                  ElevatedButton(
                    onPressed: () {
                      Navigator.pushReplacement(
                        context,
                        MaterialPageRoute(builder: (context) => loginScreen()),
                      );
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.redAccent,
                      padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(30),
                      ),
                    ),
                    child: const Text(
                      "Cancel",
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
                    ),
                  ),
                  // Done Button
                  ElevatedButton(
                    onPressed: () {
                      // Handle Done Action
                      Navigator.pushReplacement(
                        context,
                        MaterialPageRoute(builder: (context)=>mainHomepage(groupName: "Test Group")),
                      );
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.teal[700],
                      padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(30),
                      ),
                    ),
                    child: const Text(
                      "Done",
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
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
  }) {
    return TextField(
      controller: controller,
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
