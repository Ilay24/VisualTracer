// JavaScript for the Visual Traceroute tool

// Initialize map
let map;
let markers = [];
let path;

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Leaflet map
    map = L.map('map').setView([0, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    // Set up form submission
    const form = document.getElementById('traceroute-form');
    if (form) {
        form.addEventListener('submit', submitTraceroute);
    }

    // Check if we have a history item to display
    const historyData = document.getElementById('history-data');
    if (historyData) {
        try {
            const data = JSON.parse(historyData.textContent);
            displayTracerouteResults(data);
        } catch (e) {
            console.error('Failed to parse history data:', e);
        }
    }
});

// Submit traceroute request
function submitTraceroute(event) {
    event.preventDefault();

    const target = document.getElementById('target').value;
    if (!target) return;

    // Show loading state
    const button = document.getElementById('run-traceroute');
    button.disabled = true;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running...';

    // Clear previous results
    clearMap();
    document.getElementById('hop-results').innerHTML = '';

    // Call the backend API
    fetch('/tools/traceroute/run', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: target })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // Reset button
        button.disabled = false;
        button.innerHTML = '<i class="fas fa-network-wired"></i> Run Traceroute';

        // Display results
        document.getElementById('results-card').style.display = 'block';
        displayTracerouteResults(data);
    })
    .catch(error => {
        // Reset button
        button.disabled = false;
        button.innerHTML = '<i class="fas fa-network-wired"></i> Run Traceroute';

        // Show error
        showError('Error: ' + error.message);
    });
}

// Display traceroute results
function displayTracerouteResults(data) {
    const hopsContainer = document.getElementById('hop-results');
    hopsContainer.innerHTML = '';

    const coordinates = [];

    const markerGroup = L.layerGroup().addTo(map);
    const markerIcon = (hopNum) => L.divIcon({
        className: 'hop-marker-icon',
        html: `<div style="background-color: #007bff; color: white; border-radius: 50%; width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; font-size: 12px;">${hopNum}</div>`
    });

    data.hops.forEach(hop => {
        const hopEl = document.createElement('div');
        hopEl.className = 'hop-info';

        let locationText = 'Unknown Location';
        if (hop.location && hop.location.city !== 'Unknown') {
            locationText = `${hop.location.city}, ${hop.location.region}, ${hop.location.country}`;
        }

        hopEl.innerHTML = `
            <strong>Hop ${hop.hop}</strong>: ${hop.ip}
            <div><small>${locationText}</small></div>
        `;

        hopsContainer.appendChild(hopEl);

        if (hop.location && hop.location.loc) {
            const [lat, lng] = hop.location.loc.split(',').map(parseFloat);
            if (!isNaN(lat) && !isNaN(lng)) {
                coordinates.push([lat, lng]);

                const marker = L.marker([lat, lng], {
                    icon: markerIcon(hop.hop)
                }).addTo(markerGroup);

                marker.bindPopup(`<b>Hop ${hop.hop}</b><br>${hop.ip}<br>${locationText}`);
                markers.push(marker);
            }
        }
    });

    if (coordinates.length >= 2) {
        path = L.polyline(coordinates, {color: 'blue'}).addTo(map);
        map.fitBounds(path.getBounds());
    } else if (coordinates.length === 1) {
        map.setView(coordinates[0], 10);
    }

    const markerCluster = L.markerClusterGroup();
    markerGroup.eachLayer(layer => markerCluster.addLayer(layer));
    map.addLayer(markerCluster);
}


// Clear map elements
function clearMap() {
    // Remove all markers
    markers.forEach(marker => {
        map.removeLayer(marker);
    });
    markers = [];

    // Remove path
    if (path) {
        map.removeLayer(path);
        path = null;
    }

    // Reset view
    map.setView([0, 0], 2);
}