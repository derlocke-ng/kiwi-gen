// Kiwi Key Generator Theme Controller
class ThemeController {
  constructor() {
    this.initializeElements();
    this.loadSavedThemes();
    this.setupEventListeners();
  }

  initializeElements() {
    console.log('Initializing theme elements...');
    
    // Theme popup elements
    this.openThemeBtn = document.getElementById('openTheme');
    this.closeThemeBtn = document.getElementById('closeTheme');
    this.themePopup = document.getElementById('themePopup');
    this.contentSlider = document.getElementById('contentSlider');
    this.headerSlider = document.getElementById('headerSlider');
    this.darkModeToggle = document.getElementById('darkModeToggle');
    this.resetThemeBtn = document.getElementById('resetTheme');
    this.contentValue = document.getElementById('contentValue');
    this.headerValue = document.getElementById('headerValue');
    
    // Color preview elements
    this.contentPreview = document.getElementById('contentPreview');
    this.headerPreview = document.getElementById('headerPreview');
    this.contentSwatch = document.getElementById('contentSwatch');
    this.headerSwatch = document.getElementById('headerSwatch');
    
    console.log('Theme elements initialized');
  }

  loadSavedThemes() {
    // Load saved themes or use defaults
    const savedContentHue = localStorage.getItem('kiwi-gen-contentHue') || '100';
    const savedHeaderHue = localStorage.getItem('kiwi-gen-headerHue') || '210';
    const savedDarkMode = localStorage.getItem('kiwi-gen-darkMode') === 'true';

    // Apply slider values
    if (this.contentSlider) {
      this.contentSlider.value = savedContentHue;
      if (this.contentValue) this.contentValue.textContent = savedContentHue + '°';
    }
    if (this.headerSlider) {
      this.headerSlider.value = savedHeaderHue;
      if (this.headerValue) this.headerValue.textContent = savedHeaderHue + '°';
    }

    // Update color previews
    this.updateColorPreviews('content', savedContentHue, savedDarkMode);
    this.updateColorPreviews('header', savedHeaderHue, savedDarkMode);

    // Update toggle button text
    this.updateDarkModeButtons(savedDarkMode);
    
    // Apply themes immediately
    this.updateTheme('content', savedContentHue);
    this.updateTheme('header', savedHeaderHue);
    this.updateTheme('darkMode', savedDarkMode);
  }

  setupEventListeners() {
    // Theme popup controls
    if (this.openThemeBtn) {
      this.openThemeBtn.addEventListener('click', () => {
        this.showThemePopup();
      });
    }

    if (this.closeThemeBtn) {
      this.closeThemeBtn.addEventListener('click', () => {
        this.hideThemePopup();
      });
    }

    if (this.themePopup) {
      this.themePopup.addEventListener('click', (e) => {
        if (e.target === this.themePopup) {
          this.hideThemePopup();
        }
      });
    }

    // Content slider
    if (this.contentSlider) {
      this.contentSlider.addEventListener('input', (e) => {
        const isDark = localStorage.getItem('kiwi-gen-darkMode') === 'true';
        this.updateTheme('content', e.target.value);
        this.updateColorPreviews('content', e.target.value, isDark);
        if (this.contentValue) this.contentValue.textContent = e.target.value + '°';
        localStorage.setItem('kiwi-gen-contentHue', e.target.value);
      });
    }

    // Header slider
    if (this.headerSlider) {
      this.headerSlider.addEventListener('input', (e) => {
        const isDark = localStorage.getItem('kiwi-gen-darkMode') === 'true';
        this.updateTheme('header', e.target.value);
        this.updateColorPreviews('header', e.target.value, isDark);
        if (this.headerValue) this.headerValue.textContent = e.target.value + '°';
        localStorage.setItem('kiwi-gen-headerHue', e.target.value);
      });
    }

    // Dark mode toggle
    if (this.darkModeToggle) {
      this.darkModeToggle.addEventListener('click', () => {
        this.toggleDarkMode();
      });
    }

    // Reset theme button
    if (this.resetThemeBtn) {
      this.resetThemeBtn.addEventListener('click', () => {
        this.resetToDefaults();
      });
    }

    // Color swatch click handlers for copying color values
    if (this.contentSwatch) {
      this.contentSwatch.addEventListener('click', () => {
        this.copyColorValue('content');
      });
    }

    if (this.headerSwatch) {
      this.headerSwatch.addEventListener('click', () => {
        this.copyColorValue('header');
      });
    }

    // Color preview click handlers for copying color values
    if (this.contentPreview) {
      this.contentPreview.addEventListener('click', () => {
        this.copyColorValue('content-preview');
      });
    }

    if (this.headerPreview) {
      this.headerPreview.addEventListener('click', () => {
        this.copyColorValue('header-preview');
      });
    }
  }

  showThemePopup() {
    if (this.themePopup) {
      this.themePopup.classList.add('show');
    }
  }

  hideThemePopup() {
    if (this.themePopup) {
      this.themePopup.classList.remove('show');
    }
  }

  toggleDarkMode() {
    const currentMode = localStorage.getItem('kiwi-gen-darkMode') === 'true';
    const newMode = !currentMode;
    const contentHue = this.contentSlider ? this.contentSlider.value : '100';
    const headerHue = this.headerSlider ? this.headerSlider.value : '210';
    
    this.updateTheme('darkMode', newMode);
    this.updateDarkModeButtons(newMode);
    this.updateColorPreviews('content', contentHue, newMode);
    this.updateColorPreviews('header', headerHue, newMode);
    localStorage.setItem('kiwi-gen-darkMode', newMode.toString());
  }

  updateColorPreviews(area, hue, isDark = false) {
    if (area === 'content') {
      const lightness = isDark ? 40 : 55;
      const saturation = 45;
      const previewColor = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
      const swatchColor = `hsl(${hue}, 60%, ${isDark ? 35 : 45}%)`;
      
      if (this.contentPreview) {
        this.contentPreview.style.background = previewColor;
        this.contentPreview.setAttribute('data-color', previewColor);
        this.contentPreview.setAttribute('title', `Click to copy: ${previewColor}`);
      }
      if (this.contentSwatch) {
        this.contentSwatch.style.background = swatchColor;
        this.contentSwatch.setAttribute('data-color', swatchColor);
        this.contentSwatch.setAttribute('title', `Click to copy: ${swatchColor}`);
      }
    } else if (area === 'header') {
      const lightness = isDark ? 15 : 25;
      const saturation = 25;
      const previewColor = `hsl(${hue}, ${saturation}%, ${lightness}%)`;
      const swatchColor = `hsl(${hue}, 60%, ${isDark ? 55 : 65}%)`;
      
      if (this.headerPreview) {
        this.headerPreview.style.background = previewColor;
        this.headerPreview.setAttribute('data-color', previewColor);
        this.headerPreview.setAttribute('title', `Click to copy: ${previewColor}`);
      }
      if (this.headerSwatch) {
        this.headerSwatch.style.background = swatchColor;
        this.headerSwatch.setAttribute('data-color', swatchColor);
        this.headerSwatch.setAttribute('title', `Click to copy: ${swatchColor}`);
      }
    }
  }

  updateTheme(area, value) {
    const root = document.documentElement;
    
    switch(area) {
      case 'content':
        root.style.setProperty('--content-hue', value);
        break;
      case 'header':
        root.style.setProperty('--header-hue', value);
        break;
      case 'darkMode':
        root.style.setProperty('--dark-mode', value ? '1' : '0');
        break;
    }
  }

  updateDarkModeButtons(isDark) {
    if (this.darkModeToggle) {
      this.darkModeToggle.textContent = isDark ? '☀️ Light Mode' : '🌙 Dark Mode';
    }
  }

  copyColorValue(area) {
    let colorValue = '';
    let element = null;
    
    if (area === 'content' && this.contentSwatch) {
      colorValue = this.contentSwatch.getAttribute('data-color');
      element = this.contentSwatch;
    } else if (area === 'header' && this.headerSwatch) {
      colorValue = this.headerSwatch.getAttribute('data-color');
      element = this.headerSwatch;
    } else if (area === 'content-preview' && this.contentPreview) {
      colorValue = this.contentPreview.getAttribute('data-color');
      element = this.contentPreview;
    } else if (area === 'header-preview' && this.headerPreview) {
      colorValue = this.headerPreview.getAttribute('data-color');
      element = this.headerPreview;
    }
    
    if (colorValue && element) {
      // Copy to clipboard
      navigator.clipboard.writeText(colorValue).then(() => {
        // Add visual feedback
        element.classList.add('copied');
        setTimeout(() => {
          element.classList.remove('copied');
        }, 300);
        
        // Show notification if available
        if (typeof showNotification === 'function') {
          showNotification(`Copied ${area} color: ${colorValue}`, 'success');
        }
      }).catch(err => {
        console.error('Failed to copy color value:', err);
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = colorValue;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        
        if (typeof showNotification === 'function') {
          showNotification(`Copied ${area} color: ${colorValue}`, 'success');
        }
      });
    }
  }

  // Reset themes to defaults
  resetToDefaults() {
    if (typeof showNotification === 'function') {
      showNotification('Resetting theme to defaults...', 'info');
    }
    
    // Clear localStorage
    localStorage.removeItem('kiwi-gen-contentHue');
    localStorage.removeItem('kiwi-gen-headerHue');
    localStorage.removeItem('kiwi-gen-darkMode');
    
    // Reset to default values
    const defaultContentHue = '100';
    const defaultHeaderHue = '210';
    const defaultDarkMode = false;
    
    // Update sliders
    if (this.contentSlider) {
      this.contentSlider.value = defaultContentHue;
      if (this.contentValue) this.contentValue.textContent = defaultContentHue + '°';
    }
    if (this.headerSlider) {
      this.headerSlider.value = defaultHeaderHue;
      if (this.headerValue) this.headerValue.textContent = defaultHeaderHue + '°';
    }
    
    // Update color previews
    this.updateColorPreviews('content', defaultContentHue, defaultDarkMode);
    this.updateColorPreviews('header', defaultHeaderHue, defaultDarkMode);
    
    // Update dark mode button
    this.updateDarkModeButtons(defaultDarkMode);
    
    // Apply themes
    this.updateTheme('content', defaultContentHue);
    this.updateTheme('header', defaultHeaderHue);
    this.updateTheme('darkMode', defaultDarkMode);
    
    if (typeof showNotification === 'function') {
      showNotification('Theme reset to defaults!', 'success');
    }
  }

  // Static method to reset themes to defaults (legacy)
  static resetToDefaults() {
    localStorage.removeItem('kiwi-gen-contentHue');
    localStorage.removeItem('kiwi-gen-headerHue');
    localStorage.removeItem('kiwi-gen-darkMode');
    location.reload();
  }
}

// Initialize theme controller when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM loaded, initializing ThemeController...');
  try {
    window.themeController = new ThemeController();
    console.log('ThemeController initialized successfully');
  } catch (error) {
    console.error('Error initializing ThemeController:', error);
  }
});
