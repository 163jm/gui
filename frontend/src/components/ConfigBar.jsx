import React from 'react'
import './ConfigBar.css'

export default function ConfigBar({ configPath, onSelectConfig, onImport, onSubscription, onClear, nodeCount, loading }) {
  return (
    <div className="config-bar">
      <div className="config-path-area" onClick={onSelectConfig} title={configPath || '点击选择配置文件'}>
        <span className="config-path-icon">⚙</span>
        <span className="config-path-text">
          {configPath ? configPath : <span className="config-path-placeholder">点击选择 sing-box 配置文件…</span>}
        </span>
      </div>
      <div className="config-actions">
        <button className="action-btn" onClick={onImport} disabled={loading} title="从剪贴板或文本导入节点链接">
          <span className="btn-icon">⊕</span>
          导入节点
        </button>
        <button className="action-btn" onClick={onSubscription} disabled={loading} title="拉取/管理订阅">
          <span className="btn-icon">↻</span>
          订阅
        </button>
        <button className="action-btn danger" onClick={onClear} disabled={loading} title="清空所有节点">
          <span className="btn-icon">⊗</span>
          清空
        </button>
        <span className="node-count">{nodeCount} 个节点</span>
      </div>
    </div>
  )
}
