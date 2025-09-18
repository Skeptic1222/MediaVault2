// Test script for migration endpoints
// This script tests the admin migration endpoints

async function testMigrationEndpoints() {
  const baseUrl = 'http://localhost:5000';
  
  console.log('Testing Migration Endpoints...');
  console.log('================================\n');
  
  // Test 1: Sync Media to Files
  console.log('1. Testing POST /api/admin/sync-media-to-files');
  try {
    const response = await fetch(`${baseUrl}/api/admin/sync-media-to-files`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include', // Include cookies for authentication
    });
    
    if (!response.ok) {
      const error = await response.json();
      console.log(`   ❌ Failed: ${response.status} - ${error.message}`);
    } else {
      const result = await response.json();
      console.log(`   ✅ Success: ${result.message}`);
      console.log(`      - Synced: ${result.details.synced} files`);
      console.log(`      - Skipped: ${result.details.skipped} files`);
      console.log(`      - Total: ${result.details.total} files`);
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`);
  }
  
  console.log('');
  
  // Test 2: Cleanup Duplicate Categories
  console.log('2. Testing GET /api/admin/cleanup-duplicate-categories');
  try {
    const response = await fetch(`${baseUrl}/api/admin/cleanup-duplicate-categories`, {
      method: 'GET',
      credentials: 'include', // Include cookies for authentication
    });
    
    if (!response.ok) {
      const error = await response.json();
      console.log(`   ❌ Failed: ${response.status} - ${error.message}`);
    } else {
      const result = await response.json();
      console.log(`   ✅ Success: ${result.message}`);
      console.log(`      - Removed: ${result.details.removed} duplicates`);
      console.log(`      - Kept: ${result.details.kept} categories`);
      console.log(`      - Updated: ${result.details.updated} media files`);
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`);
  }
  
  console.log('');
  
  // Test 3: Verify Files API combines folders and files
  console.log('3. Testing GET /api/files (verify combination of files and folders)');
  try {
    const response = await fetch(`${baseUrl}/api/files`, {
      method: 'GET',
      credentials: 'include', // Include cookies for authentication
    });
    
    if (!response.ok) {
      const error = await response.json();
      console.log(`   ❌ Failed: ${response.status} - ${error.message}`);
    } else {
      const items = await response.json();
      const folders = items.filter(item => item.type === 'folder');
      const files = items.filter(item => item.type === 'file');
      
      console.log(`   ✅ Success: Retrieved ${items.length} items`);
      console.log(`      - Folders: ${folders.length}`);
      console.log(`      - Files: ${files.length}`);
      
      // Verify folders come before files
      if (items.length > 0) {
        let foldersSorted = true;
        let firstFileIndex = items.findIndex(item => item.type === 'file');
        let lastFolderIndex = folders.length > 0 ? items.lastIndexOf(items.find(i => i.type === 'folder')) : -1;
        
        if (firstFileIndex !== -1 && lastFolderIndex !== -1 && firstFileIndex < lastFolderIndex) {
          foldersSorted = false;
        }
        
        console.log(`      - Folders first: ${foldersSorted ? '✅' : '❌'}`);
      }
    }
  } catch (error) {
    console.log(`   ❌ Error: ${error.message}`);
  }
  
  console.log('\n================================');
  console.log('Migration Tests Complete!');
}

// Run tests
testMigrationEndpoints();