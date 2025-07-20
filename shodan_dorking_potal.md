# Shodan dorking portal:

```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Shodan Recon Portal</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f2f2f2;
      padding: 20px;
    }
    h1 {
      text-align: center;
      color: #0057a3;
    }
    input {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      margin-bottom: 20px;
      border: 1px solid #ccc;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
    }
    th, td {
      padding: 10px;
      border: 1px solid #ccc;
      text-align: left;
    }
    th {
      background-color: #0057a3;
      color: white;
    }
    tr:nth-child(even) {
      background-color: #f0f0f0;
    }
    button.query-btn {
      padding: 6px 12px;
      font-size: 14px;
      background-color: #007bff;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }
    button.query-btn:hover {
      background-color: #0056b3;
    }
  </style>
</head>
<body>

<h1>🔍 Offline Shodan Recon Portal (with Buttons)</h1>

<label><b>Enter Target (e.g., ssl:example.com or org:"My Org"):</b></label>
<input type="text" id="targetInput" placeholder='ssl:docs.10xbanking.com' oninput="updateTable()">

<table>
  <thead>
    <tr>
      <th>Type</th>
      <th>Description</th>
      <th>Search</th>
    </tr>
  </thead>
  <tbody id="queryTable"></tbody>
</table>

<script>
  const queries = [
    ["title", "Admin Panel", 'http.title:"admin"'],
    ["title", "Dashboard", 'http.title:"dashboard"'],
    ["title", "Manager", 'http.title:"manager"'],
    ["title", "Backend", 'http.title:"backend"'],
    ["title", "Database", 'http.title:"database"'],
    ["title", "Settings", 'http.title:"settings"'],
    ["title", "Setup Wizard", 'http.title:"setup"'],
    ["title", "Control Panel", 'http.title:"control"'],
    ["title", "Welcome Page", 'http.title:"welcome"'],
    ["title", "API Endpoint", 'http.title:"api"'],
    ["title", "Proxy", 'http.title:"proxy"'],
    ["title", "Intranet", 'http.title:"intranet"'],
    ["title", "React App", 'http.title:"react"'],
    ["title", "Django Site", 'http.title:"django"'],
    ["title", "Payment", 'http.title:"payment"'],
    ["title", "Panel", 'http.title:"panel"'],
    ["title", "Console", 'http.title:"console"'],
    ["title", "Register Page", 'http.title:"register"'],
    ["title", "Client", 'http.title:"client"'],
    ["title", "Config", 'http.title:"config"'],
    ["title", "System", 'http.title:"system"'],
    ["title", "Kibana No Login", 'http.title:"Kibana" -http.title:"Login"'],
    ["html", "ArcGIS Directory", 'http.html:"ArcGIS REST Services Directory"'],
    ["html", "Admin Setup", 'http.html:"admin setup"'],
    ["html", "Drupal Install", 'http.html:"Set up database" http.html:"Drupal"'],
    ["html", "Index of /", 'http.html:"index of /"'],
    ["html", "Index of Backup", 'http.html:"index of /" http.html:"backup"'],
    ["html", "Index of tar.gz", 'http.html:"index of /" http.html:"tar.gz"'],
    ["html", "Index of .xml", 'http.html:"index of /" http.html:".xml"']
  ];

  function updateTable() {
    const target = document.getElementById("targetInput").value.trim();
    const table = document.getElementById("queryTable");
    table.innerHTML = "";

    if (!target) return;

    queries.forEach(([type, desc, q]) => {
      const finalQuery = `${target} ${q}`;
      const encoded = encodeURIComponent(finalQuery);
      const shodanURL = `https://www.shodan.io/search?query=${encoded}`;
      const row = `
        <tr>
          <td>${type}</td>
          <td>${desc}</td>
          <td><button class="query-btn" onclick="window.open('${shodanURL}', '_blank')">Search 🔎</button></td>
        </tr>`;
      table.insertAdjacentHTML("beforeend", row);
    });
  }

  updateTable(); // Initial call
</script>

</body>
</html>

```
