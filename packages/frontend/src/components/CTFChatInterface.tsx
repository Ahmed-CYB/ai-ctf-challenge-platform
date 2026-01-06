import { useState, useRef, useEffect } from 'react';
import { Button } from './ui/button';
import { Card } from './ui/card';
import { Badge } from './ui/badge';
import { Textarea } from './ui/textarea';
import { Alert, AlertDescription, AlertTitle } from './ui/alert';
import { Send, Loader2, CheckCircle2, ExternalLink, AlertCircle, Sparkles, Info } from 'lucide-react';
import { toast } from 'sonner';
import { generateCTFWithN8N } from '../services/n8nApi';
import { saveChatMessage, createSession, deleteSession } from '../services/database';

interface ChallengePlan {
  title: string;
  description: string;
  category: string;
  difficulty: string;
  estimatedSolveTime: string;
  hints: string[];
}

interface Message {
  id: string;
  type: 'user' | 'assistant' | 'status' | 'result' | 'error';
  content: string;
  status?: 'planning' | 'building' | 'deploying' | 'validating' | 'ready' | 'error';
  targetUrl?: string;
  writeupContent?: string;
  challengePlan?: ChallengePlan;
  timestamp: Date;
}

export function CTFChatInterface() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputValue, setInputValue] = useState<string>('');
  const [isGenerating, setIsGenerating] = useState(false);
  // ✅ Use sessionStorage: Persists on refresh/navigation, clears on tab close
  const [sessionId] = useState<string>(() => {
    // Check if session ID exists in sessionStorage
    const stored = sessionStorage.getItem('ctf_session_id');
    if (stored) {
      // Validate format (basic check)
      if (stored.startsWith('session-') && stored.length > 20) {
        return stored;
      }
      // Invalid format, remove and regenerate
      sessionStorage.removeItem('ctf_session_id');
    }
    // ✅ Generate cryptographically secure session ID with improved uniqueness
    // Use crypto.getRandomValues for secure randomness + timestamp + UUID-like component
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    
    // Create UUID-like component for additional uniqueness
    const uuidComponent = Array.from(array.slice(0, 8), byte => 
      byte.toString(16).padStart(2, '0')
    ).join('');
    
    // Create additional random component
    const randomString = Array.from(array.slice(8, 16), byte => 
      byte.toString(36).padStart(2, '0')
    ).join('');
    
    // Combine: timestamp + UUID component + random string for maximum uniqueness
    const newId = `session-${Date.now()}-${uuidComponent}-${randomString}`;
    sessionStorage.setItem('ctf_session_id', newId);
    return newId;
  });
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Cleanup session when tab closes (but not on refresh/navigation)
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      // Only cleanup if it's a tab close, not a refresh
      // We can't perfectly detect this, but we'll use visibilitychange as a backup
      // The sessionStorage will be cleared automatically on tab close anyway
      // This is just for backend cleanup
      if (sessionId) {
        // Use sendBeacon for reliable cleanup
        deleteSession(sessionId).catch(() => {
          // Silent fail - cleanup is best effort
        });
      }
    };

    // Use pagehide event which is more reliable than beforeunload
    const handlePageHide = (e: PageTransitionEvent) => {
      // If persisted is true, it's a page navigation (not tab close)
      // If persisted is false, it's likely a tab close
      if (!e.persisted && sessionId) {
        deleteSession(sessionId).catch(() => {
          // Silent fail - cleanup is best effort
        });
      }
    };

    window.addEventListener('pagehide', handlePageHide);
    window.addEventListener('beforeunload', handleBeforeUnload);

    return () => {
      window.removeEventListener('pagehide', handlePageHide);
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [sessionId]);

  const addMessage = (message: Omit<Message, 'id' | 'timestamp'>) => {
    setMessages(prev => [
      ...prev,
      {
        ...message,
        id: Date.now().toString(),
        timestamp: new Date()
      }
    ]);
  };

  const parseUserRequest = (input: string): { category: string; difficulty: string } | null => {
    const lowerInput = input.toLowerCase();
    
    // Extract difficulty
    let difficulty = 'Intermediate'; // default
    if (lowerInput.includes('beginner') || lowerInput.includes('easy') || lowerInput.includes('basic')) {
      difficulty = 'Beginner';
    } else if (lowerInput.includes('advanced') || lowerInput.includes('hard') || lowerInput.includes('expert')) {
      difficulty = 'Advanced';
    } else if (lowerInput.includes('intermediate') || lowerInput.includes('medium')) {
      difficulty = 'Intermediate';
    }

    // Extract category
    let category = '';
    if (lowerInput.includes('web') || lowerInput.includes('sql') || lowerInput.includes('xss')) {
      category = 'Web Exploitation';
    } else if (lowerInput.includes('crypto') || lowerInput.includes('cipher') || lowerInput.includes('encryption')) {
      category = 'Cryptography';
    } else if (lowerInput.includes('reverse') || lowerInput.includes('binary') || lowerInput.includes('disassembl')) {
      category = 'Reverse Engineering';
    } else if (lowerInput.includes('forensic') || lowerInput.includes('steganography') || lowerInput.includes('image')) {
      category = 'Forensics';
    } else if (lowerInput.includes('pwn') || lowerInput.includes('buffer') || lowerInput.includes('overflow')) {
      category = 'Binary Exploitation';
    } else if (lowerInput.includes('osint') || lowerInput.includes('intelligence') || lowerInput.includes('recon')) {
      category = 'OSINT';
    }

    if (category) {
      return { category, difficulty };
    }
    return null;
  };

  const handleSendMessage = async () => {
    const trimmedInput = inputValue.trim();
    if (!trimmedInput || isGenerating) return;

    // Add user message
    addMessage({
      type: 'user',
      content: trimmedInput
    });

    setInputValue('');
    setIsGenerating(true);

    try {
      console.log('Sending to n8n chat:', { message: trimmedInput, sessionId });
      
      // Create/update session in database
      try {
        await createSession(sessionId);
      } catch (dbError) {
        console.error('Failed to create session:', dbError);
      }

      // Save user message to database
      try {
        await saveChatMessage({
          session_id: sessionId,
          role: 'user',
          message_text: trimmedInput,
        });
      } catch (dbError) {
        console.error('Failed to save user message:', dbError);
      }
      
      // Call n8n chat endpoint
      try {
        const n8nResponse = await generateCTFWithN8N({
          message: trimmedInput,
          sessionId
        });
        
        console.log('n8n chat response:', n8nResponse);

        // Format the response text from the automation service
        let responseText = '';
        
        if (n8nResponse.success) {
          // Handle different response types
          if (n8nResponse.answer) {
            // Question response
            responseText = n8nResponse.answer;
            if (n8nResponse.additionalHelp) {
              responseText += '\n\n' + n8nResponse.additionalHelp;
            }
          } else if (n8nResponse.message) {
            // Create/Deploy response
            responseText = n8nResponse.message;
            
            if (n8nResponse.challenge) {
              responseText += '\n\n**Challenge Details:**';
              if (n8nResponse.challenge.name) responseText += `\n- Name: ${n8nResponse.challenge.name}`;
              if (n8nResponse.challenge.description) responseText += `\n- Description: ${n8nResponse.challenge.description}`;
              if (n8nResponse.challenge.difficulty) responseText += `\n- Difficulty: ${n8nResponse.challenge.difficulty}`;
              if (n8nResponse.challenge.category) responseText += `\n- Category: ${n8nResponse.challenge.category}`;
              if (n8nResponse.challenge.flag) responseText += `\n- Flag: ${n8nResponse.challenge.flag}`;
            }
            
            if (n8nResponse.deployment) {
              responseText += '\n\n**Deployment Info:**';
              responseText += `\n- URL: ${n8nResponse.deployment.url}`;
              responseText += `\n- Container: ${n8nResponse.deployment.containerName}`;
            }
            
            if (n8nResponse.nextSteps) {
              responseText += '\n\n' + n8nResponse.nextSteps;
            }
            
            if (n8nResponse.instructions) {
              responseText += '\n\n' + n8nResponse.instructions;
            }
          } else if (n8nResponse.explanation) {
            // Challenge info response
            responseText = n8nResponse.explanation;
            if (n8nResponse.deployCommand) {
              responseText += '\n\n' + n8nResponse.deployCommand;
            }
          } else {
            // Fallback
            responseText = n8nResponse.output || n8nResponse.text || JSON.stringify(n8nResponse, null, 2);
          }
        } else {
          // Error response
          responseText = n8nResponse.error || n8nResponse.message || 'An error occurred';
          if (n8nResponse.details) {
            responseText += '\n\nDetails: ' + n8nResponse.details;
          }
          if (n8nResponse.suggestion) {
            responseText += '\n\n' + n8nResponse.suggestion;
          }
        }
        
        addMessage({
          type: 'assistant',
          content: responseText
        });

        // Save assistant message to database
        try {
          await saveChatMessage({
            session_id: sessionId,
            role: 'assistant',
            message_text: responseText,
            metadata: n8nResponse,
          });
        } catch (dbError) {
          console.error('Failed to save assistant message:', dbError);
        }

        toast.success('Message sent!');

      } catch (n8nError) {
        // n8n failed - show helpful error to user
        console.error('n8n generation failed:', n8nError);
        const errorMessage = n8nError instanceof Error ? n8nError.message : 'Unknown error';
        
        // Check if it's a connection error
        if (errorMessage.includes('Cannot connect to CTF automation service') || 
            errorMessage.includes('ERR_CONNECTION_REFUSED')) {
          addMessage({
            type: 'error',
            content: `⚠️ CTF Automation Service is not running.\n\nTo generate challenges, you need to start the CTF automation service on port 4003.\n\nYour message has been saved, but challenge generation is currently unavailable.`,
          });
          toast.error('CTF automation service is not available', {
            description: 'The service on port 4003 needs to be running to generate challenges.',
            duration: 5000,
          });
        } else {
          addMessage({
            type: 'error',
            content: `Failed to generate challenge. Error: ${errorMessage}`,
          });
          toast.error('Challenge generation failed');
        }
      }

    } catch (error) {
      addMessage({
        type: 'error',
        content: `Sorry, I encountered an error: ${error instanceof Error ? error.message : 'Unknown error'}. Please try again.`
      });
      toast.error('Failed to get response');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = textareaRef.current.scrollHeight + 'px';
    }
  }, [inputValue]);

  const [showWriteup, setShowWriteup] = useState(false);
  const [currentWriteup, setCurrentWriteup] = useState<string>('');

  const handleViewWriteup = (content: string) => {
    setCurrentWriteup(content);
    setShowWriteup(true);
  };

  return (
    <div className="flex flex-col h-full max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-border bg-card">
        <div className="bg-primary text-primary-foreground p-2 rounded-lg">
          <Sparkles className="w-5 h-5" />
        </div>
        <div className="flex-1">
          <h3>AI Challenge Generator</h3>
        </div>
      </div>

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-6">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex gap-3 ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            {message.type !== 'user' && (
              <div className="flex-shrink-0">
                <div className="bg-primary text-primary-foreground p-2 rounded-lg w-8 h-8 flex items-center justify-center">
                  <Sparkles className="w-4 h-4" />
                </div>
              </div>
            )}
            
            <div
              className={`max-w-[85%] md:max-w-[75%] ${
                message.type === 'user' ? 'order-first' : ''
              }`}
            >
              <div
                className={`rounded-2xl p-4 ${
                  message.type === 'user'
                    ? 'bg-primary text-primary-foreground ml-auto'
                    : message.type === 'error'
                    ? 'bg-destructive/10 border border-destructive'
                    : message.type === 'status'
                    ? 'bg-muted/50 border border-border'
                    : message.type === 'result'
                    ? 'bg-card border border-primary'
                    : 'bg-muted'
                }`}
              >
                {message.type === 'status' && (
                  <div className="flex items-center gap-2 mb-2">
                    {message.status === 'ready' ? (
                      <CheckCircle2 className="w-4 h-4 text-green-600" />
                    ) : message.status === 'error' ? (
                      <AlertCircle className="w-4 h-4 text-destructive" />
                    ) : (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    )}
                    <Badge variant={message.status === 'ready' ? 'default' : message.status === 'error' ? 'destructive' : 'secondary'}>
                      {message.status?.toUpperCase()}
                    </Badge>
                  </div>
                )}

                {message.type === 'error' && (
                  <div className="flex items-center gap-2 mb-2">
                    <AlertCircle className="w-4 h-4 text-destructive" />
                    <Badge variant="destructive">ERROR</Badge>
                  </div>
                )}
                
                <p className="whitespace-pre-wrap">{message.content}</p>

                {message.type === 'result' && message.targetUrl && (
                  <div className="mt-4 space-y-3 pt-3 border-t border-border">
                    {message.challengePlan && (
                      <div className="mb-3 p-3 bg-muted/50 rounded">
                        <p className="text-muted-foreground mb-2">Challenge Details:</p>
                        <div className="space-y-1">
                          <p><span className="font-medium">Category:</span> {message.challengePlan.category}</p>
                          <p><span className="font-medium">Difficulty:</span> {message.challengePlan.difficulty}</p>
                          <p><span className="font-medium">Estimated Time:</span> {message.challengePlan.estimatedSolveTime}</p>
                          <p className="text-muted-foreground mt-2">{message.challengePlan.description}</p>
                        </div>
                      </div>
                    )}

                    <div className="flex items-center justify-between gap-4">
                      <div className="flex-1">
                        <p className="text-muted-foreground mb-1">Target URL:</p>
                        <code className="bg-muted px-3 py-1.5 rounded block font-mono break-all">
                          {message.targetUrl}
                        </code>
                      </div>
                      <Button size="sm" variant="outline" asChild>
                        <a href={message.targetUrl} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="w-4 h-4 mr-2" />
                          Open
                        </a>
                      </Button>
                    </div>
                    
                    {message.writeupContent && (
                      <div className="flex items-center justify-between gap-4">
                        <div className="flex-1">
                          <p className="text-muted-foreground mb-1">Solution Write-up:</p>
                          <code className="bg-muted px-3 py-1.5 rounded block font-mono">
                            Available
                          </code>
                        </div>
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => handleViewWriteup(message.writeupContent!)}
                        >
                          <ExternalLink className="w-4 h-4 mr-2" />
                          View
                        </Button>
                      </div>
                    )}

                    {message.challengePlan && message.challengePlan.hints.length > 0 && (
                      <div className="p-3 bg-muted/50 rounded">
                        <p className="text-muted-foreground mb-2">Hints Available:</p>
                        <p className="text-sm">{message.challengePlan.hints.length} hints ready when you need them</p>
                      </div>
                    )}

                    <div className="pt-2">
                      <p className="text-muted-foreground">
                        Challenge will auto-terminate in 2 hours. Good luck! 🚩
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {message.type === 'user' && (
              <div className="flex-shrink-0">
                <div className="bg-muted p-2 rounded-lg w-8 h-8 flex items-center justify-center">
                  <span>👤</span>
                </div>
              </div>
            )}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Section */}
      <div className="border-t border-border p-4 bg-card">
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <Textarea
              ref={textareaRef}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyPress}
              placeholder="Ask me to create a challenge... (e.g., 'Create a beginner web exploitation challenge')"
              disabled={isGenerating}
              className="min-h-[52px] max-h-[200px] resize-none"
              rows={1}
            />
          </div>
          <Button
            onClick={handleSendMessage}
            disabled={isGenerating || !inputValue.trim()}
            size="icon"
            className="h-[52px] w-[52px] flex-shrink-0"
          >
            {isGenerating ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <Send className="w-5 h-5" />
            )}
          </Button>
        </div>
        <p className="text-muted-foreground mt-2">
          Press Enter to send, Shift+Enter for new line
        </p>
      </div>

      {/* Writeup Modal */}
      {showWriteup && (
        <div 
          className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setShowWriteup(false)}
        >
          <Card 
            className="w-full max-w-3xl max-h-[80vh] overflow-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h2>Solution Writeup</h2>
                <Button variant="outline" size="sm" onClick={() => setShowWriteup(false)}>
                  Close
                </Button>
              </div>
              <div className="prose prose-sm max-w-none">
                <pre className="whitespace-pre-wrap bg-muted p-4 rounded-lg overflow-auto">
                  {currentWriteup}
                </pre>
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
