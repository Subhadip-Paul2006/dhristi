import { useState, useEffect } from 'react';
import {
 Box, Card, CardContent, Typography, CircularProgress, Alert, Chip,
 Button, Tabs, Tab, Paper,
} from '@mui/material';
import ReactFlow, { Background, Controls, MiniMap } from 'reactflow';
import 'reactflow/dist/style.css';
import { pathsApi, type AttackPath } from '../api/paths';
import { graphApi, type GraphData } from '../api/graph';
import { Link as LinkIcon } from '@mui/icons-material';

function convertGraphToFlow(data: GraphData) {
 const nodeTypes: Record<string, string> = {
 asset: 'default',
 internet: 'input',
 dmz: 'default',
 internal: 'default',
 cloud: 'default',
 critical: 'output',
 };

 return {
 nodes: data.nodes.map((n) => ({
 id: n.id,
 data: { label: `${n.label}${n.ip ? ` (${n.ip})` : ''}` },
 type: nodeTypes[n.type] || 'default',
 position: { x: Math.random() * 400, y: Math.random() * 400 },
 style: {
 background: n.type === 'critical' ? '#f44336' : n.type === 'internet' ? '#ff9800' : '#1565c0',
 color: '#fff',
 border: '2px solid #42a5f5',
 borderRadius: 8,
 padding: 8,
 minWidth: 120,
 },
 })),
 edges: data.edges.map((e) => ({
 id: e.id,
 source: e.source,
 target: e.target,
 label: e.attack_vector || e.label,
 animated: e.attack_vector === 'exploited',
 })),
 };
}

export default function Paths() {
 const [tab, setTab] = useState(0);
 const [paths, setPaths] = useState<AttackPath[]>([]);
 const [graphData, setGraphData] = useState<GraphData | null>(null);
 const [flowData, setFlowData] = useState<any>(null);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState('');

 useEffect(() => {
 Promise.all([pathsApi.list(), graphApi.getGraph()])
 .then(([pathsRes, graphRes]) => {
 setPaths(pathsRes);
 setGraphData(graphRes);
 setFlowData(convertGraphToFlow(graphRes));
 })
 .catch((e) => setError(e.message))
 .finally(() => setLoading(false));
 }, []);

 if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', mt: 10 }}><CircularProgress /></Box>;
 if (error) return <Alert severity="error">{error}</Alert>;

 return (
 <Box>
 <Typography variant="h4" sx={{ color: '#e3f2fd', fontWeight: 600, mb: 3 }}>Attack Paths</Typography>
 <Card sx={{ background: '#0d2137', border: '1px solid rgba(66,165,245,0.15)' }}>
 <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
 <Tabs value={tab} onChange={(_, v) => setTab(v)} textColor="primary" indicatorColor="primary">
 <Tab label="Path List" />
 <Tab label="Network Graph" />
 </Tabs>
 </Box>
 <CardContent>
 {tab === 0 && (
 <Box>
 {paths.map((p) => (
 <Paper key={p.id} sx={{ p: 2, mb: 2, background: '#0a1929', border: '1px solid rgba(66,165,245,0.1)' }}>
 <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
 <Box>
 <Typography variant="h6" sx={{ color: '#e3f2fd' }}>{p.name}</Typography>
 <Typography variant="body2" sx={{ color: '#90a4ae' }}>Path: {p.path.join(' → ')}</Typography>
 {p.ai_explanation && <Typography variant="caption" sx={{ color: '#42a5f5', mt: 0.5, display: 'block' }}>AI: {p.ai_explanation}</Typography>}
 </Box>
 <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
 <Chip label={`Risk: ${p.risk_score}`} color="error" size="small" />
 <Chip label={`$${p.estimated_exposure_usd.toLocaleString()}`} color="warning" size="small" />
 </Box>
 </Box>
 </Paper>
 ))}
 </Box>
 )}
 {tab === 0 && graphData && (
 <Box sx={{ mt: 3 }}>
 <Typography variant="h6" sx={{ color: '#42a5f5', mb: 1 }}>Live Network Summary</Typography>
 <Typography variant="body2" sx={{ color: '#90a4ae' }}>
 Devices: {graphData.live_devices} | Active Threats: {graphData.network_threats} | Zones: {graphData.zones.join(', ')}
 </Typography>
 </Box>
 )}
 {tab === 1 && flowData && (
 <Box sx={{ height: 600, background: '#0a1929', borderRadius: 2 }}>
 <ReactFlow
 nodes={flowData.nodes}
 edges={flowData.edges}
 fitView
 >
 <Background gap={16} size={1} color="#1a2f45" />
 <Controls />
 <MiniMap nodeColor={(n) => (n.style?.background as string) || '#1565c0'} />
 </ReactFlow>
 </Box>
 )}
 </CardContent>
 </Card>
 </Box>
 );
}
