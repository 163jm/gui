// Bridge to Wails Go backend
// In production, window.go is injected by Wails runtime
// In dev, we mock it

const isWails = () => typeof window !== 'undefined' && window.go

export const api = {
  // Nodes
  GetNodes: () => call('GetNodes'),
  ImportNodes: (content) => call('ImportNodes', content),
  FetchSubscription: (url) => call('FetchSubscription', url),
  ClearNodes: () => call('ClearNodes'),
  DeleteNode: (id) => call('DeleteNode', id),
  UpdateNode: (node) => call('UpdateNode', node),
  ApplyNode: (id) => call('ApplyNode', id),

  // Settings
  GetSettings: () => call('GetSettings'),
  SelectConfigFile: () => call('SelectConfigFile'),
  GetSubscriptions: () => call('GetSubscriptions'),
  RemoveSubscription: (url) => call('RemoveSubscription', url),
  RefreshSubscription: (url) => call('RefreshSubscription', url),
  GetConfigPreview: () => call('GetConfigPreview'),

  // TUN
  EnableTun: () => call('EnableTun'),
  DisableTun: () => call('DisableTun'),

  // System proxy
  EnableSystemProxy: () => call('EnableSystemProxy'),
  DisableSystemProxy: () => call('DisableSystemProxy'),

  // SingBox
  StartSingBox: () => call('StartSingBox'),
  StopSingBox: () => call('StopSingBox'),
  GetSingBoxStatus: () => call('GetSingBoxStatus'),
  GetSingBoxLog: () => call('GetSingBoxLog'),
}

async function call(method, ...args) {
  if (!isWails()) {
    return mockCall(method, ...args)
  }
  return window.go.main.App[method](...args)
}

// ─── Dev mock ─────────────────────────────────────────────────────────────────
let mockNodes = [
  { id: '1', name: '香港节点 01', protocol: 'vmess', address: 'hk1.example.com', port: 443, sub_url: 'https://sub.example.com/token' },
  { id: '2', name: '日本节点 01', protocol: 'vless', address: 'jp1.example.com', port: 8443, sub_url: '' },
  { id: '3', name: '新加坡 hysteria2', protocol: 'hysteria2', address: 'sg1.example.com', port: 1234, sub_url: '' },
  { id: '4', name: '美国 trojan', protocol: 'trojan', address: 'us1.example.com', port: 443, sub_url: '' },
  { id: '5', name: 'TUIC v5 SG', protocol: 'tuic', address: 'sg2.example.com', port: 8443, sub_url: 'https://sub.example.com/token' },
]
let mockSettings = { config_path: 'C:\\Users\\user\\singbox\\config.json', subscriptions: ['https://sub.example.com/token'] }
let mockStatus = { running: false, pid: 0 }
let mockLog = ['[程序启动] SingBox GUI 已就绪']

async function mockCall(method, ...args) {
  await new Promise(r => setTimeout(r, 120))
  switch (method) {
    case 'GetNodes': return [...mockNodes]
    case 'ImportNodes': return 2
    case 'FetchSubscription': mockNodes.push({ id: Date.now().toString(), name: '新订阅节点', protocol: 'vmess', address: 'new.example.com', port: 443, sub_url: args[0] }); return 1
    case 'ClearNodes': mockNodes = []; return null
    case 'DeleteNode': mockNodes = mockNodes.filter(n => n.id !== args[0]); return null
    case 'ApplyNode': return null
    case 'GetSettings': return { ...mockSettings }
    case 'SelectConfigFile': mockSettings.config_path = 'C:\\Users\\user\\singbox\\config.json'; return mockSettings.config_path
    case 'GetSubscriptions': return [...mockSettings.subscriptions]
    case 'RemoveSubscription': mockSettings.subscriptions = mockSettings.subscriptions.filter(s => s !== args[0]); return null
    case 'RefreshSubscription': return 3
    case 'GetConfigPreview': return '{\n  "log": {},\n  "inbounds": [],\n  "outbounds": [{"tag":"proxy","type":"vless"}]\n}'
    case 'EnableTun': return null
    case 'DisableTun': return null
    case 'EnableSystemProxy': return null
    case 'DisableSystemProxy': return null
    case 'StartSingBox': mockStatus = { running: true, pid: 12345 }; mockLog.push('[15:30:00] sing-box 已启动 PID=12345'); return null
    case 'StopSingBox': mockStatus = { running: false, pid: 0 }; mockLog.push('[15:30:05] sing-box 已停止'); return null
    case 'GetSingBoxStatus': return { ...mockStatus }
    case 'GetSingBoxLog': return [...mockLog]
    default: return null
  }
}
