import { useState, useEffect } from 'react';
import {
 Box, Card, CardContent, Typography, Button, Table, TableBody,
 TableCell, TableHead, TableRow, Chip, TextField, Dialog, DialogTitle,
 DialogContent, DialogActions, CircularProgress, Alert,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';

interface User {
 id: string;
 username: string;
 email: string;
 full_name: string;
 role: string;
 is_active: boolean;
 created_at: string;
}

export default function Admin() {
 const [users, setUsers] = useState<User[]>([]);
 const [loading, setLoading] = useState(true);
 const [dialogOpen, setDialogOpen] = useState(false);
 const [formData, setFormData] = useState({ username: '', email: '', full_name: '', role: 'analyst', password: '' });

 useEffect(() => {
 setTimeout(() => {
 setUsers([
 { id: '1', username: 'admin', email: 'admin@drishti.io', full_name: 'Admin User', role: 'admin', is_active: true, created_at: '2026-01-01' },
 { id: '2', username: 'analyst', email: 'analyst@drishti.io', full_name: 'Security Analyst', role: 'analyst', is_active: true, created_at: '2026-02-15' },
 ]);
 setLoading(false);
 }, 500);
 }, []);

 const roleColor: Record<string, 'error' | 'warning' | 'info'> = { admin: 'error', analyst: 'info', viewer: 'default' };

 return (
 <Box>
 <Typography variant="h4" sx={{ color: '#e3f2fd', fontWeight: 600, mb: 3 }}>Admin — User Management</Typography>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <CardContent>
 <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
 <Typography variant="h6" sx={{ color: '#e3f2fd' }}>Users</Typography>
 <Button variant="contained" startIcon={<AddIcon />} onClick={() => setDialogOpen(true)} sx={{ background: 'linear-gradient(90deg, #1565c0, #42a5f5)' }}>
 Add User
 </Button>
 </Box>
 <Table>
 <TableHead>
 <TableRow>
 <TableCell sx={{ color: '#90a4ae' }}>Username</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Email</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Full Name</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Role</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Active</TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>Created</TableCell>
 </TableRow>
 </TableHead>
 <TableBody>
 {users.map((u) => (
 <TableRow key={u.id}>
 <TableCell sx={{ color: '#e3f2fd' }}>{u.username}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{u.email}</TableCell>
 <TableCell sx={{ color: '#e3f2fd' }}>{u.full_name}</TableCell>
 <TableCell><Chip label={u.role} color={roleColor[u.role] as any || 'default'} size="small" /></TableCell>
 <TableCell><Chip label={u.is_active ? 'Yes' : 'No'} color={u.is_active ? 'success' : 'default'} size="small" /></TableCell>
 <TableCell sx={{ color: '#90a4ae' }}>{new Date(u.created_at).toLocaleDateString()}</TableCell>
 </TableRow>
 ))}
 </TableBody>
 </Table>
 </CardContent>
 </Card>

 <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)}>
 <DialogTitle sx={{ color: '#e3f2fd' }}>Add User</DialogTitle>
 <DialogContent>
 <TextField label="Username" fullWidth margin="dense" onChange={(e) => setFormData({ ...formData, username: e.target.value })} />
 <TextField label="Email" fullWidth margin="dense" onChange={(e) => setFormData({ ...formData, email: e.target.value })} />
 <TextField label="Full Name" fullWidth margin="dense" onChange={(e) => setFormData({ ...formData, full_name: e.target.value })} />
 <TextField label="Password" type="password" fullWidth margin="dense" onChange={(e) => setFormData({ ...formData, password: e.target.value })} />
 </DialogContent>
 <DialogActions>
 <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
 <Button variant="contained" onClick={() => setDialogOpen(false)} sx={{ background: 'linear-gradient(90deg, #1565c0, #42a5f5)' }}>Save</Button>
 </DialogActions>
 </Dialog>
 </Box>
 );
}
