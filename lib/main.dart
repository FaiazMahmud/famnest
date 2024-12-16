import 'package:flutter/material.dart';
import 'package:laboratory/testapp/splashScreen.dart';
import 'testapp/loginScreen.dart';




void main(){
  runApp(const MyApp());
}

class MyApp extends StatelessWidget{
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {

    return MaterialApp(
      debugShowCheckedModeBanner: false,
      initialRoute: '/',
      routes: {
        '/':(context)=> splashScreen(),
        '/home': (context) => loginScreen(),// Replace HomeScreen with your main screen
      },
    );
  }

}


