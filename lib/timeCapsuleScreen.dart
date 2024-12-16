import 'package:flutter/material.dart';

class timeCapsuleScreen extends StatefulWidget {
  @override
  _TimeCapsuleScreenState createState() => _TimeCapsuleScreenState();
}

class _TimeCapsuleScreenState extends State<timeCapsuleScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final TextEditingController _searchController = TextEditingController();
  String selectedCategory = "Images"; // Default category
  String searchQuery = "";
  bool isSearchBarVisible = false; // Controls the visibility of the search bar

  // Sample data for each category
  final Map<String, List<String>> categoryData = {
    "Images": ["Family Photo", "Holiday Pic"],
    "Videos": ["Birthday Celebration", "Vacation Clip"],
    "Voices": ["Grandma's Advice", "Kids Laughing"],
    "Stories": ["Vacation Story", "Family Journal"]
  };

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    _tabController.addListener(() {
      setState(() {
        selectedCategory = ["Images", "Videos", "Voices", "Stories"][_tabController.index];
        _searchController.clear(); // Clear search query on tab change
        searchQuery = "";
      });
    });
  }

  @override
  void dispose() {
    _tabController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Time Capsule'),
        actions: [
          IconButton(
            icon: Icon(isSearchBarVisible ? Icons.close : Icons.search),
            onPressed: () {
              setState(() {
                isSearchBarVisible = !isSearchBarVisible; // Toggle search bar visibility
                if (!isSearchBarVisible) {
                  _searchController.clear(); // Clear the search query when hiding the search bar
                  searchQuery = "";
                }
              });
            },
          ),
        ],
        bottom: PreferredSize(
          preferredSize: isSearchBarVisible ? const Size.fromHeight(150) : const Size.fromHeight(50),
          child: Column(
            children: [
              if (isSearchBarVisible)
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8.0),
                  child: TextField(
                    controller: _searchController,
                    decoration: InputDecoration(
                      hintText: "Search $selectedCategory...",
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(30.0),
                      ),
                    ),
                    onChanged: (value) {
                      setState(() {
                        searchQuery = value;
                      });
                    },
                  ),
                ),
              TabBar(
                controller: _tabController,
                tabs: const [
                  Tab(icon: Icon(Icons.image), text: "Images"),
                  Tab(icon: Icon(Icons.videocam), text: "Videos"),
                  Tab(icon: Icon(Icons.mic), text: "Voices"),
                  Tab(icon: Icon(Icons.book), text: "Stories"),
                ],
              ),
            ],
          ),
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildFilteredList("Images"),
          _buildFilteredList("Videos"),
          _buildFilteredList("Voices"),
          _buildFilteredStories(),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _showAddItemDialog,
        child: const Icon(Icons.add),
      ),
    );
  }

  Widget _buildFilteredList(String type) {
    final items = categoryData[type]!;
    final filteredItems = items
        .where((item) => item.toLowerCase().contains(searchQuery.toLowerCase()))
        .toList();

    if (filteredItems.isEmpty) {
      return const Center(child: Text("No items found."));
    }

    return ListView.builder(
      itemCount: filteredItems.length,
      itemBuilder: (context, index) {
        return ListTile(
          leading: type == "Images"
              ? const Icon(Icons.image)
              : type == "Videos"
              ? const Icon(Icons.videocam)
              : const Icon(Icons.mic),
          title: Text(filteredItems[index]),
          onTap: () {
            // Handle item click
          },
        );
      },
    );
  }

  Widget _buildFilteredStories() {
    final stories = categoryData["Stories"]!;
    final filteredStories = stories
        .where((story) => story.toLowerCase().contains(searchQuery.toLowerCase()))
        .toList();

    if (filteredStories.isEmpty) {
      return const Center(child: Text("No stories found."));
    }

    return ListView.builder(
      itemCount: filteredStories.length,
      itemBuilder: (context, index) {
        return ListTile(
          leading: const Icon(Icons.book),
          title: Text(filteredStories[index]),
          onTap: () {
            // Handle story click
          },
        );
      },
    );
  }

  void _showAddItemDialog() {
    showDialog(
      context: context,
      builder: (context) {
        return AddItemDialog(category: selectedCategory);
      },
    );
  }
}

class AddItemDialog extends StatefulWidget {
  final String category;

  const AddItemDialog({required this.category});

  @override
  _AddItemDialogState createState() => _AddItemDialogState();
}

class _AddItemDialogState extends State<AddItemDialog> {
  final TextEditingController titleController = TextEditingController();
  final TextEditingController descriptionController = TextEditingController();
  final TextEditingController tagsController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text("Add ${widget.category}"),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: titleController,
              decoration: const InputDecoration(labelText: "Title"),
            ),
            TextField(
              controller: descriptionController,
              decoration: const InputDecoration(labelText: "Description"),
            ),
            TextField(
              controller: tagsController,
              decoration: const InputDecoration(labelText: "Tags (comma-separated)"),
            ),
            if (widget.category != "Stories")
              ElevatedButton(
                onPressed: () {
                  // Handle file picker for images, videos, or voices
                },
                child: const Text("Choose File"),
              ),
            if (widget.category == "Stories")
              TextField(
                maxLines: 5,
                decoration: const InputDecoration(hintText: "Write your story here..."),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text("Cancel"),
        ),
        ElevatedButton(
          onPressed: () {
            // Handle saving the item
            Navigator.pop(context);
          },
          child: const Text("Save"),
        ),
      ],
    );
  }
}
