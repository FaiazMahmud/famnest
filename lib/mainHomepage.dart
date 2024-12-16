import 'dart:async';
import 'package:flutter/material.dart';
import 'package:testapp/timeCapsuleScreen.dart';  // Import the TimeCapsuleScreen

class mainHomepage extends StatefulWidget {
  final String groupName;

  mainHomepage({required this.groupName});

  @override
  _MainHomepageState createState() => _MainHomepageState();
}

class _MainHomepageState extends State<mainHomepage> {
  int _currentIndex = 0;
  int _selectedGridIndex = -1;
  final PageController _pageController = PageController();
  late Timer _timer;
  int _currentPage = 0;

  final List<String> _slideshowImages = [
    'assets/slideshowimages/slide1.jpg',
    'assets/slideshowimages/slide2.png',
    'assets/slideshowimages/slide3.jpg',
  ];

  final List<IconData> _gridIcons = [
    Icons.bar_chart,
    Icons.folder,
    Icons.event,
    Icons.picture_in_picture_alt_sharp,
  ];

  final List<String> _headlines = [
    'Expense Tracking',
    'Documents',
    'Plan Events',
    'Memories',
  ];

  final List<String> _descriptions = [
    'Track your family expenses effortlessly.',
    'Store and access important documents.',
    'Keep track of upcoming events.',
    'Save precious family moments.',
  ];

  final List<Color> _colors = [
    Colors.teal[300]!,
    Colors.teal[400]!,
    Colors.teal[500]!,
    Colors.teal[600]!,
  ];

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 3), (timer) {
      if (_pageController.hasClients) {
        final nextPage = (_currentPage + 1) % _slideshowImages.length;
        _pageController.animateToPage(
          nextPage,
          duration: const Duration(milliseconds: 500),
          curve: Curves.easeInOut,
        );
        setState(() {
          _currentPage = nextPage;
        });
      }
    });
  }

  @override
  void dispose() {
    _timer.cancel();
    _pageController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.groupName),
        backgroundColor: Colors.teal,
        actions: [
          IconButton(
            icon: Icon(Icons.search),
            onPressed: () {
              // Handle search
            },
          ),
        ],
      ),
      drawer: Drawer(
        child: ListView(
          padding: EdgeInsets.zero,
          children: [
            DrawerHeader(
              decoration: BoxDecoration(
                color: Colors.teal,
              ),
              child: Text(
                'Menu',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 24,
                ),
              ),
            ),
            ListTile(
              leading: Icon(Icons.home),
              title: Text('Home'),
              onTap: () {
                Navigator.pop(context);
              },
            ),
            ListTile(
              leading: Icon(Icons.group),
              title: Text('Groups'),
              onTap: () {
                // Handle navigation
              },
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          // Slideshow Section
          SizedBox(
            height: 220,
            child: Stack(
              alignment: Alignment.bottomCenter,
              children: [
                PageView.builder(
                  controller: _pageController,
                  itemCount: _slideshowImages.length,
                  itemBuilder: (context, index) {
                    return Container(
                      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(8),
                        child: Image.asset(
                          _slideshowImages[index],
                          fit: BoxFit.cover,
                        ),
                      ),
                    );
                  },
                ),
                Positioned(
                  bottom: 0,
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: List.generate(
                      _slideshowImages.length,
                          (index) => AnimatedContainer(
                        duration: const Duration(milliseconds: 300),
                        margin: const EdgeInsets.symmetric(horizontal: 4),
                        height: 8,
                        width: _currentPage == index ? 16 : 8,
                        decoration: BoxDecoration(
                          color: _currentPage == index ? Colors.teal : Colors.grey,
                          borderRadius: BorderRadius.circular(4),
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 25),
          // Grid Section
          Expanded(
            child: GridView.builder(
              gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: 2,
                crossAxisSpacing: 16,
                mainAxisSpacing: 16,
                childAspectRatio: 1,
              ),
              padding: const EdgeInsets.all(16),
              itemCount: _gridIcons.length,
              itemBuilder: (context, index) {
                return GestureDetector(
                  onTap: () {
                    if (index == 3) {
                      // Navigate to TimeCapsuleScreen when the "Memories" grid item is tapped
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (context) => timeCapsuleScreen()),
                      );
                    }
                  },
                  child: AnimatedContainer(
                    duration: const Duration(milliseconds: 300),
                    curve: Curves.easeInOut,
                    decoration: BoxDecoration(
                      color: _colors[index],
                      borderRadius: BorderRadius.circular(10),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withOpacity(0.2),
                          blurRadius: 8,
                          offset: Offset(0, 4),
                        ),
                      ],
                    ),
                    child: Padding(
                      padding: const EdgeInsets.all(12.0),
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Icon(_gridIcons[index], size: 40, color: Colors.white),
                          const SizedBox(height: 8),
                          Text(
                            _headlines[index],
                            style: const TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _descriptions[index],
                            style: const TextStyle(
                              fontSize: 12,
                              color: Colors.white70,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
        ],
      ),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _currentIndex,
        onTap: (index) {
          setState(() {
            _currentIndex = index;
          });
          if (index == 0) {
            Navigator.pop(context); // Navigate to Home Page
          } else if (index == 1) {
            // Navigate to Create Group
          } else if (index == 2) {
            // Navigate to Groups Page
          }
        },
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.home),
            label: 'Home',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.add),
            label: 'Create Group',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.group),
            label: 'Groups',
          ),
        ],
        selectedItemColor: Colors.teal[800],
        unselectedItemColor: Colors.teal[400],
        backgroundColor: Colors.white,
        showUnselectedLabels: true,
      ),
    );
  }
}
