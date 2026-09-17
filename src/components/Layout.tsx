import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import {
 AppBar,
 Toolbar,
 Typography,
 CssBaseline,
 useMediaQuery,
 useTheme,
 Box,
 IconButton,
} from '@mui/material';
import { Menu as MenuIcon } from '@mui/icons-material';
import Sidebar from './Sidebar';

export default function Layout() {
 const theme = useTheme();
 const isMobile = useMediaQuery(theme.breakpoints.down('md'));
 const [mobileOpen, setMobileOpen] = useState(false);

 const icons: Record<string, React.ReactNode> = {};

 return (
 <Box sx={{ display: 'flex' }}>
 <CssBaseline />
 <AppBar position="fixed" sx={{ zIndex: (t: any) => t.zIndex.drawer + 1, boxShadow: 'none', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
 <Toolbar sx={{ background: 'linear-gradient(90deg, #0d47a1 0%, #1565c0 100%)' }}>
 <IconButton color="inherit" edge="start" onClick={() => setMobileOpen(!mobileOpen)} sx={{ mr: 2, display: { md: 'none' } }}>
 <MenuIcon />
 </IconButton>
 <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1, color: '#fff' }}>
 Cybersecurity Platform
 </Typography>
 </Toolbar>
 </AppBar>
 <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} icons={icons} />
 <Box component="main" sx={{ flexGrow: 1, p: 3, width: { md: 'calc(100% - 260px)' }, minHeight: '100vh', background: '#0a1929' }}>
 <Toolbar />
 <Outlet />
 </Box>
 </Box>
 );
}
