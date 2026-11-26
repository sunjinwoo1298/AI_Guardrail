# Extractable components

#### Layout Components

## Sidebar
- Source: `frontend/src/App.jsx` (the `<aside className="sidebar">` block)
- Category: layout
- Description: Brand, view navigation, connection status and settings, session counters
- Extractable props: activeItem (string, default: "playground"), online (boolean, default: true)
- Hardcoded: brand text, nav labels, form labels, CSS

#### Basic Components

## ResultPanel
- Source: `frontend/src/components/ResultPanel.jsx`
- Category: basic
- Description: Status tags plus metadata and security key/value details for one request
- Extractable props: status (number, default: 200)
- Hardcoded: field labels, tag styles
