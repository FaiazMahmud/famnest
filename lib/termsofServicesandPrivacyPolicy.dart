import 'package:flutter/material.dart';

class termsOfServicesAndPrivacyPolicy {
  static void showTermsOfServices(BuildContext context) {
    showModalBottomSheet(
      context: context,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      isScrollControlled: true,
      builder: (BuildContext context) {
        return _buildFloatingContent(
          context,
          title: "Terms of Services",
          content: """
**FamNest Terms of Service**

**Last Updated: December 10, 2024**

Welcome to FamNest! By accessing or using our mobile application, you agree to comply with and be bound by the following Terms of Service. Please read these terms carefully. If you do not agree, please refrain from using our services.

---

**1. Acceptance of Terms**
By creating an account or using FamNest, you agree to abide by these Terms of Service and our Privacy Policy. These terms apply to all users, including family members who share access.

---

**2. Use of Services**
FamNest provides tools for families to:
- Manage and track financial expenses.
- Store and access important documents.
- Manage family events via a shared calendar.
- Store family memories such as photos, videos, and stories.
- Maintain a directory of important contacts.

You agree to use these services responsibly and only for lawful purposes.

---

**3. User Responsibilities**
You are responsible for:
- Maintaining the confidentiality of your account credentials.
- Ensuring all information provided is accurate and up-to-date.
- Respecting the privacy of other family members who share access.

FamNest is not liable for any loss or damage resulting from unauthorized access due to your failure to secure your account.

---

**4. Privacy and Data Protection**
Your privacy is important to us. By using FamNest, you consent to the collection and use of your data as outlined in our Privacy Policy. We use your data only to enhance your experience and do not share it with third parties without your consent.

---

**5. Prohibited Activities**
You agree not to:
- Use FamNest for illegal, fraudulent, or harmful purposes.
- Upload content that is offensive, defamatory, or violates intellectual property rights.
- Attempt to hack, disrupt, or reverse-engineer the application.

---

**6. Content Ownership**
You retain ownership of the content you upload, such as photos, videos, and documents. By uploading content, you grant FamNest a non-exclusive license to store and display it within the app for your use.

---

**7. Termination**
We reserve the right to suspend or terminate your account if you violate these Terms of Service. Upon termination, your access to the app and its features will be revoked.

---

**8. Limitation of Liability**
FamNest is provided on an 'as-is' basis. While we strive to ensure the app functions smoothly, we are not liable for:
- Technical issues, bugs, or downtime.
- Loss of data due to user actions or unforeseen circumstances.
- Any indirect, incidental, or consequential damages.

---

**9. Modifications to Terms**
We may update these Terms of Service from time to time. Any changes will be communicated through the app. Continued use of FamNest signifies your acceptance of the updated terms.

---

**10. Governing Law**
These terms are governed by and construed under the laws of your jurisdiction. Any disputes shall be resolved exclusively in courts located in your region.

---

**11. Contact Us**
If you have any questions or concerns about these terms, please contact us at support@famnest.com.

---

By signing up and using FamNest, you agree to these terms. Thank you for being part of the FamNest community!
          """,
        );
      },
    );
  }

  static void showPrivacyPolicy(BuildContext context) {
    showModalBottomSheet(
      context: context,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      isScrollControlled: true,
      builder: (BuildContext context) {
        return _buildFloatingContent(
          context,
          title: "Privacy Policy",
          content: """
"Privacy Policy for FamNest"

"Last Updated: December 10, 2024"

"At FamNest, your privacy is important to us. This Privacy Policy outlines the types of information we collect, how we use and protect your data, and your rights regarding your personal information."

---

"1. Information We Collect"
"We collect the following types of information to provide and improve our services:"
"- Personal Information: Name, email address, phone number, and password."
"- Family Information: Data related to family members such as names, contact details, and roles."
"- Financial Data: Expenses, income, and budgeting information for your family."
"- Event and Document Data: Data on events, calendars, and documents uploaded to the app."
"- User Activity: Information on app usage and preferences."

---

"2. How We Use Your Information"
"We use the collected information to:"
"- Provide services such as financial tracking, event management, and document storage."
"- Improve the app and provide personalized content."
"- Send updates and notifications with your consent."
"- Ensure the security of your data and prevent fraud."

---

"3. Sharing of Information"
"We do not sell or share your personal information with third parties for marketing purposes. We may share data with:"
"- Service Providers: Trusted third-party companies who help operate our app."
"- Legal Authorities: If required to comply with legal obligations or protect rights."
"- Business Transfers: In the case of a merger or acquisition."

---

"4. Data Security"
"We use industry-standard encryption and security measures to protect your information. However, no system is completely secure, and we cannot guarantee absolute security."

---

"5. Your Rights and Choices"
"You have the right to:"
"- Access and update your personal information."
"- Delete your account and data by contacting support."
"- Opt-out of marketing communications at any time."

---

"6. Data Retention"
"We retain your data only as long as necessary to provide our services and comply with legal obligations. Afterward, your data is securely deleted."

---

"7. Children’s Privacy"
"FamNest is not intended for children under 13 years old, and we do not knowingly collect data from children."

---

"8. Changes to This Privacy Policy"
"We may update this policy from time to time. Any changes will be posted on this page, and you will be notified through the app."

---

"9. Contact Us"
"If you have any questions or concerns about your privacy, please contact us at support@famnest.com."

---

"By using FamNest, you agree to this Privacy Policy. Thank you for trusting FamNest with your data!"
""",
        );
      },
    );
  }

  static Widget _buildFloatingContent(BuildContext context,
      {required String title, required String content}) {
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.8,
      minChildSize: 0.5,
      maxChildSize: 0.9,
      builder: (BuildContext context, ScrollController scrollController) {
        return Container(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Container(
                width: 50,
                height: 5,
                margin: const EdgeInsets.only(bottom: 16),
                decoration: BoxDecoration(
                  color: Colors.grey[300],
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              Text(
                title,
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: Colors.teal[800],
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 10),
              Expanded(
                child: SingleChildScrollView(
                  controller: scrollController,
                  child: Text(
                    content,
                    style: TextStyle(fontSize: 14, color: Colors.teal[600]),
                  ),
                ),
              ),
              const SizedBox(height: 10),
              ElevatedButton(
                onPressed: () => Navigator.pop(context),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.teal[700],
                  padding: const EdgeInsets.symmetric(horizontal: 50, vertical: 15),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(30),
                  ),
                ),
                child: const Text(
                  "Close",
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}
