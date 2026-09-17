// @ts-nocheck
import { Renderer, Program, Mesh, Triangle, Geometry } from 'ogl';
import React, { useEffect, useRef, useMemo } from 'react';
import './NeuralBackground.css';

interface NeuralBackgroundProps {
 color?: string;
 particleCount?: number;
 connectionDistance?: number;
 speed?: number;
 trailOpacity?: number;
}

interface Particle {
 x: number;
 y: number;
 z: number;
 vx: number;
 vy: number;
 vz: number;
}

const vertexShader = `
attribute vec3 position;
attribute vec3 color;
attribute float size;

uniform mat4 modelViewMatrix;
uniform mat4 projectionMatrix;
uniform float uTime;
uniform float uPixelRatio;

varying vec3 vColor;
varying float vAlpha;

void main() {
 vec3 pos = position;

 // Subtle wave motion
 float wave = sin(pos.x * 2.0 + uTime * 0.5) * cos(pos.y * 2.0 + uTime * 0.3) * 0.02;
 pos.z += wave;

 vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);

 gl_PointSize = size * uPixelRatio * (200.0 / -mvPosition.z);
 gl_Position = projectionMatrix * mvPosition;

 vColor = color;
 vAlpha = smoothstep(800.0, 100.0, -mvPosition.z);
}
`;

const fragmentShader = `
precision highp float;

varying vec3 vColor;
varying float vAlpha;

void main() {
 float dist = length(gl_PointCoord - vec2(0.5));
 if (dist > 0.5) discard;

 float alpha = smoothstep(0.5, 0.1, dist) * vAlpha * 0.9;

 // Soft glow
 float glow = exp(-dist * 4.0) * 0.5;
 vec3 color = vColor + glow * 0.3;

 gl_FragColor = vec4(color, alpha);
}
`;

const lineVertexShader = `
attribute vec3 position;
attribute vec3 color;
attribute float alpha;

uniform mat4 modelViewMatrix;
uniform mat4 projectionMatrix;
uniform float uTime;

varying vec3 vColor;
varying float vAlpha;

void main() {
 vec3 pos = position;

 float wave = sin(pos.x * 2.0 + uTime * 0.5) * cos(pos.y * 2.0 + uTime * 0.3) * 0.02;
 pos.z += wave;

 gl_Position = projectionMatrix * modelViewMatrix * vec4(pos, 1.0);
 vColor = color;
 vAlpha = alpha;
}
`;

const lineFragmentShader = `
precision highp float;

varying vec3 vColor;
varying float vAlpha;

void main() {
 gl_FragColor = vec4(vColor, vAlpha * 0.35);
}
`;

export default function NeuralBackground({
 color = '#38c6f4',
 particleCount = 150,
 connectionDistance = 150,
 speed = 0.8,
 trailOpacity = 0.1,
}: NeuralBackgroundProps) {
 const containerRef = useRef<HTMLDivElement>(null);
 const particlesRef = useRef<Particle[]>([]);
 const programRef = useRef<any>(null);
 const lineProgramRef = useRef<any>(null);
 const meshRef = useRef<any>(null);
 const lineMeshRef = useRef<any>(null);
 const animationFrameRef = useRef<number>(0);

 const { particleColor, lineColor } = useMemo(() => {
 const r = parseInt(color.slice(1, 3), 16) / 255;
 const g = parseInt(color.slice(3, 5), 16) / 255;
 const b = parseInt(color.slice(5, 7), 16) / 255;
 return {
 particleColor: [r, g, b] as [number, number, number],
 lineColor: [r, g, b] as [number, number, number],
 };
 }, [color]);

 useEffect(() => {
 if (!containerRef.current) return;
 const container = containerRef.current;
 const rect = container.getBoundingClientRect();
 const width = rect.width || window.innerWidth;
 const height = rect.height || window.innerHeight;

 // Initialize renderer
 const renderer = new Renderer({
 alpha: true,
 premultipliedAlpha: false,
 antialias: true,
 dpr: Math.min(window.devicePixelRatio, 2),
 });
 const gl = renderer.gl;
 gl.clearColor(0, 0, 0, 0);
 gl.enable(gl.BLEND);
 gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
 container.appendChild(gl.canvas);
 gl.canvas.style.position = 'absolute';
 gl.canvas.style.inset = '0';
 gl.canvas.style.width = '100%';
 gl.canvas.style.height = '100%';
 gl.canvas.style.pointerEvents = 'none';

 // Camera setup (orthographic-like via perspective)
 const camera = {
 position: [0, 0, 600],
 projection: () => {
 const aspect = width / height;
 const fov = (60 * Math.PI) / 180;
 const near = 1;
 const far = 2000;
 const f = 1 / Math.tan(fov / 2);
 return new Float32Array([
 f / aspect, 0, 0, 0,
 0, f, 0, 0,
 0, 0, (far + near) / (near - far), -1,
 0, 0, (2 * far * near) / (near - far), 0,
 ]);
 },
 };

 // Initialize particles
 const particles: Particle[] = [];
 for (let i = 0; i < particleCount; i++) {
 particles.push({
 x: (Math.random() - 0.5) * width * 1.5,
 y: (Math.random() - 0.5) * height * 1.5,
 z: (Math.random() - 0.5) * 400,
 vx: (Math.random() - 0.5) * speed * 0.5,
 vy: (Math.random() - 0.5) * speed * 0.5,
 vz: (Math.random() - 0.5) * speed * 0.2,
 });
 }
 particlesRef.current = particles;

 // Create particle geometry
 const particleGeometry = new Geometry(gl, {
 position: { size: 3, data: new Float32Array(particleCount * 3) },
 color: { size: 3, data: new Float32Array(particleCount * 3) },
 size: { size: 1, data: new Float32Array(particleCount) },
 });

 // Create line geometry (max connections = particleCount * 6)
 const maxLines = particleCount * 6;
 const lineGeometry = new Geometry(gl, {
 position: { size: 3, data: new Float32Array(maxLines * 6) },
 color: { size: 3, data: new Float32Array(maxLines * 6) },
 alpha: { size: 1, data: new Float32Array(maxLines * 2) },
 });

 // Particle program
 const particleProgram = new Program(gl, {
 vertex: vertexShader,
 fragment: fragmentShader,
 transparent: true,
 depthTest: false,
 uniforms: {
 uTime: { value: 0 },
 uPixelRatio: { value: Math.min(window.devicePixelRatio, 2) },
 projectionMatrix: { value: camera.projection() },
 modelViewMatrix: { value: new Float32Array(16) },
 },
 });
 programRef.current = particleProgram;

 // Line program
 const lineProgram = new Program(gl, {
 vertex: lineVertexShader,
 fragment: lineFragmentShader,
 transparent: true,
 depthTest: false,
 uniforms: {
 uTime: { value: 0 },
 projectionMatrix: { value: camera.projection() },
 modelViewMatrix: { value: new Float32Array(16) },
 },
 });
 lineProgramRef.current = lineProgram;

 // Create meshes
 const particleMesh = new Mesh(gl, {
 geometry: particleGeometry,
 program: particleProgram,
 mode: gl.POINTS,
 });
 meshRef.current = particleMesh;

 const lineMesh = new Mesh(gl, {
 geometry: lineGeometry,
 program: lineProgram,
 mode: gl.LINES,
 });
 lineMeshRef.current = lineMesh;

 // Scene
 const scene = { children: [particleMesh, lineMesh] } as any;

 function resize() {
 const w = container.offsetWidth || window.innerWidth;
 const h = container.offsetHeight || window.innerHeight;
 renderer.setSize(w, h);
 const proj = camera.projection();
 particleProgram.uniforms.projectionMatrix.value = proj;
 lineProgram.uniforms.projectionMatrix.value = proj;
 }
 resize();
 window.addEventListener('resize', resize);

 let time = 0;
 function update() {
 animationFrameRef.current = requestAnimationFrame(update);
 time += 0.016;

 // Update particles
 const positions = particleGeometry.attributes.position.data;
 const colors = particleGeometry.attributes.color.data;
 const sizes = particleGeometry.attributes.size.data;

 for (let i = 0; i < particles.length; i++) {
 const p = particles[i];
 p.x += p.vx;
 p.y += p.vy;
 p.z += p.vz;

 // Wrap around
 const boundX = width * 0.75;
 const boundY = height * 0.75;
 if (p.x > boundX) p.x = -boundX;
 if (p.x < -boundX) p.x = boundX;
 if (p.y > boundY) p.y = -boundY;
 if (p.y < -boundY) p.y = boundY;
 if (p.z > 200) p.z = -200;
 if (p.z < -200) p.z = 200;

 positions[i * 3] = p.x;
 positions[i * 3 + 1] = p.y;
 positions[i * 3 + 2] = p.z;

 colors[i * 3] = particleColor[0];
 colors[i * 3 + 1] = particleColor[1];
 colors[i * 3 + 2] = particleColor[2];

 sizes[i] = 2.5 + Math.random() * 1.5;
 }
 particleGeometry.attributes.position.needsUpdate = true;
 particleGeometry.attributes.color.needsUpdate = true;
 particleGeometry.attributes.size.needsUpdate = true;

 // Update connections
 const linePositions = lineGeometry.attributes.position.data;
 const lineColors = lineGeometry.attributes.color.data;
 const lineAlphas = lineGeometry.attributes.alpha.data;

 let lineIdx = 0;
 const maxDist = connectionDistance;
 const maxDistSq = maxDist * maxDist;

 for (let i = 0; i < particles.length && lineIdx < maxLines; i++) {
 for (let j = i + 1; j < particles.length && lineIdx < maxLines; j++) {
 const dx = particles[i].x - particles[j].x;
 const dy = particles[i].y - particles[j].y;
 const dz = particles[i].z - particles[j].z;
 const distSq = dx * dx + dy * dy + dz * dz;

 if (distSq < maxDistSq) {
 const alpha = 1.0 - distSq / maxDistSq;
 const idx = lineIdx * 6;

 linePositions[idx] = particles[i].x;
 linePositions[idx + 1] = particles[i].y;
 linePositions[idx + 2] = particles[i].z;
 linePositions[idx + 3] = particles[j].x;
 linePositions[idx + 4] = particles[j].y;
 linePositions[idx + 5] = particles[j].z;

 lineColors[idx] = lineColor[0];
 lineColors[idx + 1] = lineColor[1];
 lineColors[idx + 2] = lineColor[2];
 lineColors[idx + 3] = lineColor[0];
 lineColors[idx + 4] = lineColor[1];
 lineColors[idx + 5] = lineColor[2];

 lineAlphas[lineIdx * 2] = alpha * trailOpacity;
 lineAlphas[lineIdx * 2 + 1] = alpha * trailOpacity;

 lineIdx++;
 }
 }
 }

 // Clear remaining lines
 for (let i = lineIdx; i < maxLines; i++) {
 lineAlphas[i * 2] = 0;
 lineAlphas[i * 2 + 1] = 0;
 }

 lineGeometry.attributes.position.needsUpdate = true;
 lineGeometry.attributes.color.needsUpdate = true;
 lineGeometry.attributes.alpha.needsUpdate = true;

 // Update uniforms
 particleProgram.uniforms.uTime.value = time;
 lineProgram.uniforms.uTime.value = time;

 // Model view matrix
 const mvMatrix = new Float32Array([
 1, 0, 0, 0,
 0, 1, 0, 0,
 0, 0, 1, 0,
 0, 0, -600, 1,
 ]);
 particleProgram.uniforms.modelViewMatrix.value = mvMatrix;
 lineProgram.uniforms.modelViewMatrix.value = mvMatrix;

 renderer.render({ scene, camera: camera as any });
 }

 update();

 return () => {
 cancelAnimationFrame(animationFrameRef.current);
 window.removeEventListener('resize', resize);
 if (gl.canvas && container.contains(gl.canvas)) {
 container.removeChild(gl.canvas);
 }
 gl.getExtension('WEBGL_lose_context')?.loseContext();
 };
 }, [color, particleCount, connectionDistance, speed, trailOpacity]);

 return (
 <div
 ref={containerRef}
 className="neural-bg-container"
 style={{
 position: 'absolute',
 inset: 0,
 overflow: 'hidden',
 pointerEvents: 'none',
 }}
 />
 );
}
