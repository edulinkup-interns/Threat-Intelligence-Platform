import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import { Toaster } from 'react-hot-toast'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <>
      <App />
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#1a1729',
            color: '#f0eeff',
            border: '1px solid #2a2540',
            fontFamily: "'Syne', sans-serif",
            fontSize: '13px',
          },
        }}
      />
    </>
  </StrictMode>
)