// Main JavaScript file for the application

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Enable Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Enable Bootstrap popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

// Confirm dialog for dangerous actions
function confirmAction(message) {
    return confirm(message || 'Are you sure you want to perform this action?');
}
function showError(message) {
    const alertHtml = `
        <div class="alert alert-danger alert-dismissible fade show">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    const alertContainer = document.createElement('div');
    alertContainer.innerHTML = alertHtml;

    document.querySelector('.container').prepend(alertContainer);
}
function showSuccess(message) {
    const alertHtml = `
        <div class="alert alert-success alert-dismissible fade show">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    const alertContainer = document.createElement('div');
    alertContainer.innerHTML = alertHtml;

    document.querySelector('.container').prepend(alertContainer);
}
function validateForm(formElement) {
    const form = document.querySelector(formElement);
    if (!form) return true;

    return form.checkValidity();
}
document.addEventListener('DOMContentLoaded', function () {
  const modeToggle = document.getElementById('mode-toggle');
  const icon = document.getElementById('mode-icon');

  function applyMode(mode) {
    if (mode === 'dark') {
      document.body.classList.add('dark-mode');
      icon.classList.remove('fa-moon');
      icon.classList.add('fa-sun');
    } else {
      document.body.classList.remove('dark-mode');
      icon.classList.remove('fa-sun');
      icon.classList.add('fa-moon');
    }
  }

  // Load saved mode
  const savedMode = localStorage.getItem('mode') || 'light';
  applyMode(savedMode);

  modeToggle.addEventListener('click', () => {
    const isDark = document.body.classList.contains('dark-mode');
    const newMode = isDark ? 'light' : 'dark';
    applyMode(newMode);
    localStorage.setItem('mode', newMode);
  });
});
document.addEventListener('DOMContentLoaded', function () {
    const animatedElements = document.querySelectorAll('h1, h3, h5, h6, .home-card p.small');

    const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-visible');
            }
        });
    }, {
        threshold: 0.1
    });

    animatedElements.forEach(el => {
        observer.observe(el);
    });
});
