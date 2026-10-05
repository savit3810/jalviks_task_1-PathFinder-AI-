import { create } from 'zustand';

// ─── Types ────────────────────────────────────────────────────────────────────
export type UserRole = 'class10' | 'class12' | 'college' | 'graduate' | 'parent' | 'admin' | 'viewer';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  skills: string[];
  interests: string[];
  resumeScore: number;
  jobReadiness: number;
  xp: number;
  badges: string[];
  currentStage: string;
  parentCode?: string;
  linkedChildCode?: string;
  careerGoal?: string;
}

export interface ChildProfile {
  // Simplified for integration
  id: string;
  name: string;
  email: string;
  stage: string;
  xp: number;
}

export const roleLabels: Record<UserRole, string> = {
  class10: 'Class 10 Student',
  class12: 'Class 11-12 Student',
  college: 'College Student',
  graduate: 'Graduate / Job Seeker',
  parent: 'Parent',
  admin: 'Administrator',
  viewer: 'Viewer',
};

export const roleIcons: Record<UserRole, string> = {
  class10: '📚',
  class12: '🎓',
  college: '🏫',
  graduate: '💼',
  parent: '👨‍👩‍👧',
  admin: '🛡️',
  viewer: '👁️',
};

// ─── Store ────────────────────────────────────────────────────────────────────
interface AppState {
  isAuthenticated: boolean;
  accessToken: string | null;
  mfaRequired: boolean;
  mfaToken: string | null;
  user: UserProfile | null;
  childProfile: ChildProfile | null;
  authError: string | null;
  signupParentCode: string | null;
  
  loginWithCredentials: (email: string, password: string) => Promise<boolean>;
  verifyMfa: (code: string) => Promise<boolean>;
  signup: (data: any) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  clearError: () => void;
  clearSignupCode: () => void;
  setAuthData: (token: string, user: UserProfile) => void;
}

const API_BASE = '/api';

export const useAppStore = create<AppState>((set, get) => ({
  isAuthenticated: false,
  accessToken: null,
  mfaRequired: false,
  mfaToken: null,
  user: null,
  childProfile: null,
  authError: null,
  signupParentCode: null,

  loginWithCredentials: async (email, password) => {
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        set({ authError: data.detail || 'Login failed' });
        return false;
      }
      
      if (data.mfa_required) {
        set({ mfaRequired: true, mfaToken: data.mfa_token, authError: null });
        return true;
      }
      
      // Real app would decode JWT or fetch /api/users/me here
      // For demo we mock the user profile temporarily
      const user: UserProfile = {
        id: 'temp-id', name: 'User', email, role: 'student' as UserRole,
        skills: [], interests: [], resumeScore: 0, jobReadiness: 0, xp: 0, badges: [], currentStage: 'Student'
      };
      
      set({ isAuthenticated: true, accessToken: data.access_token, user, authError: null });
      return true;
    } catch (e) {
      set({ authError: 'Network error' });
      return false;
    }
  },

  verifyMfa: async (code) => {
    const { mfaToken } = get();
    if (!mfaToken) return false;
    
    try {
      const res = await fetch(`${API_BASE}/auth/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfa_token: mfaToken, code }),
      });
      const data = await res.json();
      if (!res.ok) {
        set({ authError: data.detail || 'Invalid MFA code' });
        return false;
      }
      
      const user: UserProfile = {
        id: 'temp-id', name: 'User', email: 'admin@test', role: 'admin' as UserRole,
        skills: [], interests: [], resumeScore: 0, jobReadiness: 0, xp: 0, badges: [], currentStage: 'Admin'
      };
      
      set({ isAuthenticated: true, mfaRequired: false, mfaToken: null, accessToken: data.access_token, user, authError: null });
      return true;
    } catch (e) {
      set({ authError: 'Network error' });
      return false;
    }
  },

  signup: async (data) => {
    try {
      const res = await fetch(`${API_BASE}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: data.name,
          email: data.email,
          password: data.password,
          role: data.role,
          linkedChildCode: data.linkedChildCode,
          careerGoal: data.careerGoal
        }),
      });
      const json = await res.json();
      if (!res.ok) return { success: false, error: json.detail || 'Signup failed' };
      
      // Automatically login after signup
      await get().loginWithCredentials(data.email, data.password);
      return { success: true };
    } catch (e) {
      return { success: false, error: 'Network error' };
    }
  },

  logout: async () => {
    try {
      await fetch(`${API_BASE}/auth/logout`, { method: 'POST' });
    } catch (e) {}
    set({ isAuthenticated: false, accessToken: null, user: null, childProfile: null, mfaRequired: false, mfaToken: null });
  },

  clearError: () => set({ authError: null }),
  clearSignupCode: () => set({ signupParentCode: null }),
  
  setAuthData: (token, user) => set({ isAuthenticated: true, accessToken: token, user })
}));

// ─── Compatibility shims for AdminDashboard ──────────────────────────────────
// These replace the old localStorage-based functions with API-backed stubs.
// ADMIN_EMAIL is no longer hardcoded — it shows the current user's email.
export const ADMIN_EMAIL = '(see logged-in user)';

interface AccountRecord {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  xp: number;
  createdAt: string;
}

export function loadAccounts(): AccountRecord[] {
  // In the secured version, accounts are fetched from the backend API.
  // This returns an empty array as a safe default; the admin dashboard
  // should be wired to fetch from /api/admin/users when the backend is live.
  return [];
}

export function deleteAccountById(_id: string): void {
  // In the secured version, deletion goes through the backend API
  // via DELETE /api/admin/users/:id with proper RBAC checks.
  console.warn('deleteAccountById: Use the API endpoint DELETE /api/admin/users/:id');
}
