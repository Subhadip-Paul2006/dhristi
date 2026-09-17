import { useState } from 'react';
import {
 Container,
 TextField,
 Button,
 Box,
 Typography,
 Alert,
 Paper,
} from '@mui/material';
import { authApi } from '../api/auth';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

export default function Login() {
 const [username, setUsername] = useState('');
 const [password, setPassword] = useState('');
 const [loading, setLoading] = useState(false);
 const navigate = useNavigate();

 const handleSubmit = async (e: React.FormEvent) => {
 e.preventDefault();
 setLoading(true);
 try {
 const res = await authApi.login({ username, password });
 localStorage.setItem('access_token', res.access_token);
 localStorage.setItem('refresh_token', res.refresh_token);
 toast.success('Login successful');
 navigate('/dashboard');
 } catch (err: any) {
 toast.error(err.response?.data?.detail || 'Login failed');
 } finally {
 setLoading(false);
 }
 };

 return (
 <Container maxWidth="sm" sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
 <Paper elevation={6} sx={{ p: 4, width: '100%', background: '#0d2137', borderRadius: 3, border: '1px solid rgba(66, 165, 245, 0.15)' }}>
 <Typography variant="h4" align="center" sx={{ color: '#42a5f5', fontWeight: 700, mb: 1 }}>
 Drishti
 </Typography>
 <Typography variant="body2" align="center" sx={{ color: '#90a4ae', mb: 4 }}>
 Cybersecurity Platform
 </Typography>
 <Box component="form" onSubmit={handleSubmit}>
 <TextField label="Username" fullWidth margin="normal" value={username} onChange={(e) => setUsername(e.target.value)} required />
 <TextField label="Password" type="password" fullWidth margin="normal" value={password} onChange={(e) => setPassword(e.target.value)} required />
 <Button type="submit" variant="contained" fullWidth size="large" disabled={loading} sx={{ mt: 3, py: 1.2, background: 'linear-gradient(90deg, #1565c0, #42a5f5)', '&:hover': { background: 'linear-gradient(90deg, #0d47a1, #1565c0)' } }}>
 {loading ? 'Signing in...' : 'Sign In'}
 </Button>
 <Alert severity="info" sx={{ mt: 2, background: 'rgba(33, 150, 243, 0.05)', color: '#90a4ae' }}>
 Default credentials: admin / admin123
 </Alert>
 </Box>
 </Paper>
 </Container>
 );
}
