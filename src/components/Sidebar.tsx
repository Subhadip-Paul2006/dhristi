import {
 Box, Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText,
 Toolbar, Typography,
} from '@mui/material';
import { Logout as LogoutIcon } from '@mui/icons-material';
import { authApi } from '../api/auth';

const drawerWidth = 260;

interface NavItem {
 text: string;
 path: string;
 icon: React.ReactNode;
}

const navItems: NavItem[] = [
 { text: 'Dashboard', path: '/dashboard', icon: null },
 { text: 'Assets', path: '/assets', icon: null },
 { text: 'Attack Paths', path: '/paths', icon: null },
 { text: 'Live Monitoring', path: '/live', icon: null },
 { text: 'URL Trust', path: '/urltrust', icon: null },
 { text: 'Reports', path: '/reports', icon: null },
 { text: 'Admin', path: '/admin', icon: null },
];

interface SidebarProps {
 mobileOpen: boolean;
 onClose: () => void;
}

export default function Sidebar({ mobileOpen, onClose }: SidebarProps) {
 const handleLogout = async () => {
 try { await authApi.logout(); } catch {}
 localStorage.removeItem('access_token');
 localStorage.removeItem('refresh_token');
 window.location.href = '/login';
 };

 const drawerContent = (
 <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
 <Toolbar sx={{ background: 'linear-gradient(135deg, #0d47a1 0%, #1565c0 100%)' }}>
 <Typography variant="h6" noWrap sx={{ color: '#fff', fontWeight: 700, letterSpacing: 1 }}>
 Drishti
 </Typography>
 </Toolbar>
 <Box sx={{ flexGrow: 1, py: 2 }}>
 <List>
 {navItems.map((item) => (
 <ListItem key={item.text} disablePadding>
 <ListItemButton
 href={item.path}
 onClick={onClose}
 sx={{ mx: 1, borderRadius: 2, '&:hover': { bgcolor: 'rgba(33, 150, 243, 0.08)' } }}
 >
 {item.icon && <ListItemIcon sx={{ color: '#42a5f5', minWidth: 40 }}>{item.icon}</ListItemIcon>}
 <ListItemText primary={item.text} />
 </ListItemButton>
 </ListItem>
 ))}
 </List>
 </Box>
 <Box sx={{ px: 2, pb: 2 }}>
 <Box
 component="div"
 onClick={handleLogout}
 sx={{ display: 'flex', alignItems: 'center', gap: 1.5, px: 2, py: 1.5, borderRadius: 2, cursor: 'pointer', color: '#f44336' }}
 >
 <LogoutIcon sx={{ fontSize: 20 }} />
 <Typography variant="body2">Logout</Typography>
 </Box>
 </Box>
 </Box>
 );

 return (
 <>
 <Drawer
 variant="temporary"
 open={mobileOpen}
 onClose={onClose}
 ModalProps={{ keepMounted: true }}
 sx={{ display: { xs: 'block', md: 'none' }, '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth } }}
 >
 {drawerContent}
 </Drawer>
 <Drawer
 variant="permanent"
 sx={{ display: { xs: 'none', md: 'block' }, '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth, background: '#0a1929', borderRight: '1px solid rgba(255,255,255,0.05)' } }}
 open
 >
 {drawerContent}
 </Drawer>
 </>
 );
}
