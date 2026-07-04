import React, { useState, useEffect, useCallback, useRef } from 'react'
import { api } from './lib/wails'
import NodeList from './components/NodeList'
import SubscriptionModal from './components/SubscriptionModal'
import ImportModal from './components/ImportModal'
import LogPanel from './components/LogPanel'
import ConfigBar from './components/ConfigBar'
import BottomBar from './components/BottomBar'
import Toast from './components/Toast'
import './App.css'

export default function App() {
  const [nodes, setNodes] = useState([])
  const [settings, setSettings] = useState({ config_path: '', subscriptions: [] })
  const [singboxStatus, setSingboxStatus] = useState({ running: false, pid: 0 })
  const [tunEnabled, setTunEnabled] = useState(false)
  const [proxyEnabled, setProxyEnabled] = useState(false)
  const [activeTab, setActiveTab] = useState('nodes') // nodes | log
  const [showSubModal, setShowSubModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [toast, setToast] = useState(null)
  const [loading, setLoading] = useState(false)
  const pollRef = useRef(null)

  const showToast = useCallback((msg, type = 'info') => {
    setToast({ msg, type, id: Date.now() })
  }, [])

  const loadNodes = useCallback(async () => {
    try {
      const n = await api.GetNodes()
      setNodes(n || [])
    } catch (e) {
      showToast('加载节点失败: ' + e, 'error')
    }
  }, [showToast])

  const loadSettings = useCallback(async () => {
    try {
      const s = await api.GetSettings()
      setSettings(s || { config_path: '', subscriptions: [] })
    } catch (e) { /* ignore */ }
  }, [])

  useEffect(() => {
    loadNodes()
    loadSettings()

    // poll singbox status
    pollRef.current = setInterval(async () => {
      try {
        const s = await api.GetSingBoxStatus()
        setSingboxStatus(s || { running: false })
      } catch (e) { /* ignore */ }
    }, 2000)

    return () => clearInterval(pollRef.current)
  }, [loadNodes, loadSettings])

  // ─── Actions ──────────────────────────────────────────────────────────────

  const handleSelectConfig = async () => {
    try {
      const path = await api.SelectConfigFile()
      if (path) {
        setSettings(s => ({ ...s, config_path: path }))
        showToast('已选择配置文件', 'success')
      }
    } catch (e) {
      showToast('选择文件失败: ' + e, 'error')
    }
  }

  const handleImport = async (content) => {
    setLoading(true)
    try {
      const count = await api.ImportNodes(content)
      await loadNodes()
      showToast(`成功导入 ${count} 个节点`, 'success')
      setShowImportModal(false)
    } catch (e) {
      showToast('导入失败: ' + e, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleFetchSub = async (url) => {
    setLoading(true)
    try {
      const count = await api.FetchSubscription(url)
      await loadNodes()
      await loadSettings()
      showToast(`订阅更新成功，获取 ${count} 个节点`, 'success')
      setShowSubModal(false)
    } catch (e) {
      showToast('订阅拉取失败: ' + e, 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleClearNodes = async () => {
    if (!window.confirm || window.confirm('确认清空所有节点？')) {
      try {
        await api.ClearNodes()
        setNodes([])
        showToast('已清空节点列表', 'info')
      } catch (e) {
        showToast('清空失败: ' + e, 'error')
      }
    }
  }

  const handleApplyNode = async (id) => {
    try {
      await api.ApplyNode(id)
      showToast('节点已应用到配置文件', 'success')
    } catch (e) {
      showToast('应用节点失败: ' + e, 'error')
    }
  }

  const handleDeleteNode = async (id) => {
    try {
      await api.DeleteNode(id)
      setNodes(ns => ns.filter(n => n.id !== id))
    } catch (e) {
      showToast('删除失败: ' + e, 'error')
    }
  }

  // ─── Bottom bar toggles ───────────────────────────────────────────────────

  const handleToggleTun = async (on) => {
    try {
      if (on) {
        await api.EnableTun()
        setTunEnabled(true)
        showToast('已启用 TUN 模式', 'success')
      } else {
        await api.DisableTun()
        setTunEnabled(false)
        showToast('已关闭 TUN 模式', 'info')
      }
    } catch (e) {
      showToast('TUN 操作失败: ' + e, 'error')
    }
  }

  const handleToggleProxy = async (on) => {
    try {
      if (on) {
        await api.EnableSystemProxy()
        setProxyEnabled(true)
        showToast('已启用系统代理 (127.0.0.1:2080)', 'success')
      } else {
        await api.DisableSystemProxy()
        setProxyEnabled(false)
        showToast('已关闭系统代理', 'info')
      }
    } catch (e) {
      showToast('系统代理操作失败: ' + e, 'error')
    }
  }

  const handleToggleSingbox = async (on) => {
    try {
      if (on) {
        await api.StartSingBox()
        showToast('sing-box 已启动', 'success')
        setActiveTab('log')
      } else {
        await api.StopSingBox()
        showToast('sing-box 已停止', 'info')
      }
    } catch (e) {
      showToast('sing-box 操作失败: ' + e, 'error')
    }
  }

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="app">
      {/* Title bar */}
      <div className="titlebar" style={{ '--wails-draggable': 'drag' }}>
        <div className="titlebar-left">
          <span className="titlebar-icon">◈</span>
          <span className="titlebar-title">SingBox GUI</span>
        </div>
        <div className="titlebar-tabs">
          <button
            className={`tab-btn${activeTab === 'nodes' ? ' active' : ''}`}
            onClick={() => setActiveTab('nodes')}
          >节点列表</button>
          <button
            className={`tab-btn${activeTab === 'log' ? ' active' : ''}`}
            onClick={() => setActiveTab('log')}
          >
            运行日志
            {singboxStatus.running && <span className="tab-badge" />}
          </button>
        </div>
        <div className="titlebar-status">
          {singboxStatus.running
            ? <span className="status-dot running" title={`PID: ${singboxStatus.pid}`} />
            : <span className="status-dot stopped" />
          }
          <span className="status-text">
            {singboxStatus.running ? `运行中 #${singboxStatus.pid}` : '未运行'}
          </span>
        </div>
      </div>

      {/* Config bar */}
      <ConfigBar
        configPath={settings.config_path}
        onSelectConfig={handleSelectConfig}
        onImport={() => setShowImportModal(true)}
        onSubscription={() => setShowSubModal(true)}
        onClear={handleClearNodes}
        nodeCount={nodes.length}
        loading={loading}
      />

      {/* Main content */}
      <div className="main-content">
        {activeTab === 'nodes' && (
          <NodeList
            nodes={nodes}
            onApply={handleApplyNode}
            onDelete={handleDeleteNode}
            onRefresh={loadNodes}
          />
        )}
        {activeTab === 'log' && (
          <LogPanel />
        )}
      </div>

      {/* Bottom bar */}
      <BottomBar
        tunEnabled={tunEnabled}
        proxyEnabled={proxyEnabled}
        singboxRunning={singboxStatus.running}
        onToggleTun={handleToggleTun}
        onToggleProxy={handleToggleProxy}
        onToggleSingbox={handleToggleSingbox}
      />

      {/* Modals */}
      {showImportModal && (
        <ImportModal
          onConfirm={handleImport}
          onClose={() => setShowImportModal(false)}
          loading={loading}
        />
      )}
      {showSubModal && (
        <SubscriptionModal
          subscriptions={settings.subscriptions || []}
          onFetch={handleFetchSub}
          onClose={() => setShowSubModal(false)}
          loading={loading}
        />
      )}

      {/* Toast */}
      {toast && <Toast key={toast.id} message={toast.msg} type={toast.type} />}
    </div>
  )
}
