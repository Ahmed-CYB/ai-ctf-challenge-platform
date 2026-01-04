/**
 * CTF Automation API Service
 * Handles communication with the CTF automation service
 */

// Use the new automation service instead of n8n
const CTF_API_URL = import.meta.env.VITE_CTF_API_URL || 'http://localhost:4003/api/chat';

export interface CTFGenerationRequest {
  message: string;
  sessionId?: string;
}

export interface CTFChatResponse {
  output?: string;
  text?: string;
  [key: string]: any;
}

/**
 * Send a message to the CTF automation service
 * @param request - The chat request with message and session
 * @returns The chat response from the automation service
 */
export async function generateCTFWithN8N(request: CTFGenerationRequest): Promise<CTFChatResponse> {
  try {
    console.log('CTF API URL:', CTF_API_URL);
    console.log('Sending message to CTF automation service:', request);
    
    const response = await fetch(CTF_API_URL, {
      method: 'POST',
      mode: 'cors',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(request),
    });

    console.log('CTF API response status:', response.status);
    console.log('CTF API response headers:', Object.fromEntries(response.headers.entries()));

    if (!response.ok) {
      const errorText = await response.text();
      console.error('CTF API error response:', errorText);
      throw new Error(`CTF API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    console.log('CTF API response data:', data);
    return data;
  } catch (error) {
    console.error('Error calling CTF automation service:', error);
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error('Cannot connect to CTF automation service. Make sure it is running on port 4003');
    }
    throw error;
  }
}

/**
 * Check if the CTF automation service is configured and accessible
 * @returns true if the service endpoint is available
 */
export async function isN8NConfigured(): Promise<boolean> {
  try {
    const response = await fetch(CTF_API_URL.replace('/api/chat', '/health'), {
      method: 'GET',
    });
    return response.ok;
  } catch (error) {
    console.warn('CTF automation service not accessible:', error);
    return false;
  }
}
