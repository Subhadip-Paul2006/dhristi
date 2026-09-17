import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import Layout from './components/Layout';
import PrivateRoute from './components/PrivateRoute';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import Paths from './pages/Paths';
import Live from './pages/Live';
import URLTrust from './pages/URLTrust';
import Reports from './pages/Reports';
import Admin from './pages/Admin';
import toast, { Toaster } from 'react-hot-toast';

const theme = createTheme({
 palette: {
 mode: 'dark',
 primary: { main: '#42a5f5' },
 secondary: { main: '#f44336' },
 background: { default: '#0a1929', paper: '#0d2137' },
 text: { primary: '#e3f2fd', secondary: '#90a4ae' },
 },
 typography: {
 fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
 },
});

export default function App() {
 return (
 <ThemeProvider theme={theme}>
 <CssBaseline />
 <Toaster position="top-right" toastOptions={{ style: { background: '#0d2137', color: '#e3f2fd', border: '1px solid rgba(66,165,245,0.3)' } }} />
 <BrowserRouter>
 <Routes>
 <Route path="/login" element={<Login />} />
 <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
 <Route index element={<Navigate to="/dashboard" replace />} />
 <Route path="dashboard" element={<Dashboard />} />
 <Route path="assets" element={<Assets />} />
 <Route path="paths" element={<Paths />} />
 <Route path="live" element={<Live />} />
 <Route path="urltrust" element={<URLTrust />} />
 <Route path="reports" element={<Reports />} />
 <Route path="admin" element={<Admin />} />
 </Route>
 </Routes>
 </BrowserRouter>
 </ThemeProvider>
 );
}
