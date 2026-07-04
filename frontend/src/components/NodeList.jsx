import React, { useState, useEffect, useRef, useCallback } from 'react'
import './NodeList.css'

const PROTOCOL_COLORS = {
  vmess:     '#5b7cf6',
  vless:     '#3ddc84',
  trojan:    '#f59e0b',
  ss:        '#e879f9',
  hysteria2: '#f05252',
  tuic:      '#22d3ee',
}

const PROTOCOL_LABELS = {
  vmess:     'VMess',
  vless:     'VLESS',
  trojan:    'Trojan',
  ss:        'SS',
  hysteria2: 'Hy2',
  tuic:      'TUIC',
}

export default function NodeList({ nodes, onApply, onDelete, onRefresh }) {
  const [contextMenu, setContextMenu] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [search, setSearch] = useState('')
  const menuRef = useRef(null)

  const filtered = nodes.filter(n =>
    n.name?.toLowerCase().includes(search.toLowerCase()) ||
    n.address?.toLowerCase().includes(search.toLowerCase()) ||
    n.protocol?.toLowerCase().includes(search.toLowerCase())
  )

  const grouped = groupBySubURL(filtered)

  const handleContextMenu = (e, node) => {
    e.preventDefault()
    setSelectedId(node.id)
    setContextMenu({ x: e.clientX, y: e.clientY, node })
  }

  const handleClick = (node) => {
    setSelectedId(node.id)
    setContextMenu(null)
  }

  const closeMenu = useCallback(() => setContextMenu(null), [])

  useEffect(() => {
    const handler = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        closeMenu()
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [closeMenu])

  const handleApply = async () => {
    if (!contextMenu) return
    closeMenu()
    await onApply(contextMenu.node.id)
  }

  const handleDelete = async () => {
    if (!contextMenu) return
    closeMenu()
    await onDelete(contextMenu.node.id)
  }

  if (nodes.length === 0) {
    return (
      <div className="node-list-empty">
        <div className="empty-icon">◈</div>
        <div className="empty-title">暂无节点</div>
        <div className="empty-desc">点击上方「导入节点」或「订阅」添加节点</div>
      </div>
    )
  }

  return (
    <div className="node-list-wrap">
      {/* Search */}
      <div className="node-search-bar">
        <span className="search-icon">⌕</span>
        <input
          className="node-search"
          type="text"
          placeholder="搜索节点名称、地址、协议…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {search && (
          <button className="search-clear" onClick={() => setSearch('')}>✕</button>
        )}
        <span className="search-count">{filtered.length}/{nodes.length}</span>
      </div>

      {/* List */}
      <div className="node-list">
        {Object.entries(grouped).map(([subURL, groupNodes]) => (
          <div key={subURL} className="node-group">
            {subURL && (
              <div className="group-header">
                <span className="group-icon">⊞</span>
                <span className="group-url">{subURL || '手动添加'}</span>
                <span className="group-count">{groupNodes.length}</span>
              </div>
            )}
            {groupNodes.map(node => (
              <NodeRow
                key={node.id}
                node={node}
                selected={selectedId === node.id}
                onClick={() => handleClick(node)}
                onContextMenu={(e) => handleContextMenu(e, node)}
              />
            ))}
          </div>
        ))}
      </div>

      {/* Context menu */}
      {contextMenu && (
        <div
          ref={menuRef}
          className="context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          <div className="ctx-node-name">{contextMenu.node.name}</div>
          <div className="ctx-divider" />
          <button className="ctx-item primary" onClick={handleApply}>
            <span>▶</span> 应用此节点
          </button>
          <button className="ctx-item" onClick={handleDelete}>
            <span>⊗</span> 删除节点
          </button>
        </div>
      )}
    </div>
  )
}

function NodeRow({ node, selected, onClick, onContextMenu }) {
  const color = PROTOCOL_COLORS[node.protocol] || '#9ea3c0'
  const label = PROTOCOL_LABELS[node.protocol] || node.protocol?.toUpperCase()

  return (
    <div
      className={`node-row${selected ? ' selected' : ''}`}
      onClick={onClick}
      onContextMenu={onContextMenu}
    >
      <span className="node-proto-badge" style={{ color, borderColor: color + '40', background: color + '12' }}>
        {label}
      </span>
      <span className="node-name">{node.name || '未命名节点'}</span>
      <span className="node-addr">{node.address}:{node.port}</span>
    </div>
  )
}

function groupBySubURL(nodes) {
  const groups = {}
  for (const n of nodes) {
    const key = n.sub_url || ''
    if (!groups[key]) groups[key] = []
    groups[key].push(n)
  }
  return groups
}
