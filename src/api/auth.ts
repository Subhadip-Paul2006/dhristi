import { apiClient } from './client';

export interface AuthResponse {
 access_token: string;
 refresh_token: string;
 token_type?: string;
}

export interface LoginRequest {
 username: string;
 password: string;
}

export interface RegisterRequest {
 username: string;
 email: string;
 password: string;
 full_name?: string;
}

export const authApi = {
 register: async (data: RegisterRequest): Promise<AuthResponse> => {
 const res = await apiClient.post<AuthResponse>('/auth/register', data);
 return res.data;
 },

 login: async (data: LoginRequest): Promise<AuthResponse> => {
 const res = await apiClient.post<AuthResponse>('/auth/login', data);
 return res.data;
 },

 refresh: async (): Promise<AuthResponse> => {
 const refreshToken = localStorage.getItem('refresh_token');
 const res = await apiClient.post<AuthResponse>('/auth/refresh', { refresh_token: refreshToken });
 return res.data;
 },

 logout: async (): Promise<void> => {
 await apiClient.post('/auth/logout');
 },
};
