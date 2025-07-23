#!/usr/bin/env python3
# threat_hunter.py
# Description: A self-contained, advanced threat hunting tool for Wazuh with
#              long-term memory, Gemini analysis, and a real-time dashboard.
#              Enhanced with robust rate limiting, thread safety, and observability.

import os
import sys
import json
import hashlib
import time
import threading
import logging
import asyncio
import re
import html
import random
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Tuple, Any
from collections import deque, defaultdict
import math
import numpy as np
from dateutil import parser as date_parser

# --- Installation Check & Instructions ---
try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Depends, Response
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
    from fastapi.security import HTTPBasic, HTTPBasicCredentials
    from pydantic import BaseModel, Field
    from contextlib import asynccontextmanager
    import faiss
    from sentence_transformers import SentenceTransformer
    import google.generativeai as genai
    import httpx
    import aiofiles
except ImportError:
    print("="*80)
    print("ERROR: Missing required Python packages.")
    print("Please install them by running this command:")
    print("pip3 install uvicorn fastapi python-multipart sentence-transformers faiss-cpu numpy python-dateutil google-generativeai httpx aiofiles")
    print("="*80)
    exit(1)


# --- Enhanced HTML Content for Dashboard ---
HTML_CONTENT = r"""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh Threat Hunter Pro (Gemini Edition)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            --card-bg: rgba(30, 41, 59, 0.8);
            --glass-bg: rgba(51, 65, 85, 0.1);
            --border-color: rgba(148, 163, 184, 0.2);
            --text-main: #f8fafc;
            --text-secondary: #cbd5e1;
            --accent-primary: #3b82f6;
            --accent-secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --critical: #dc2626;
        }
        
        body { 
            background: var(--bg-gradient);
            color: var(--text-main);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
        }
        
        .glass-card {
            background: var(--card-bg);
            backdrop-filter: blur(20px) saturate(180%);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .glass-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }
        
        .severity-Critical { 
            border-left: 4px solid var(--critical);
            background: linear-gradient(90deg, rgba(220, 38, 38, 0.1) 0%, transparent 100%);
        }
        .severity-High { 
            border-left: 4px solid var(--danger);
            background: linear-gradient(90deg, rgba(239, 68, 68, 0.1) 0%, transparent 100%);
        }
        .severity-Medium { 
            border-left: 4px solid var(--warning);
            background: linear-gradient(90deg, rgba(245, 158, 11, 0.1) 0%, transparent 100%);
        }
        .severity-Low { 
            border-left: 4px solid var(--success);
            background: linear-gradient(90deg, rgba(16, 185, 129, 0.1) 0%, transparent 100%);
        }
        
        .modal-backdrop {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(10px);
            display: none; align-items: center; justify-content: center; z-index: 50;
            animation: fadeIn 0.2s ease-out;
        }
        
        .modal-content {
            background: var(--card-bg);
            backdrop-filter: blur(20px) saturate(180%);
            max-width: 90vw; width: 800px;
            max-height: 90vh; overflow-y: auto;
            border-radius: 1rem; padding: 2rem;
            border: 1px solid var(--border-color);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            animation: slideUp 0.3s ease-out;
            margin: 1rem;
        }
        
        @media (max-width: 768px) {
            .modal-content {
                width: 95vw;
                max-width: 95vw;
                padding: 1rem;
                margin: 0.5rem;
                max-height: 95vh;
            }
            
            .modal-content h2 {
                font-size: 1.25rem;
            }
            
            .grid.grid-cols-1.md\\:grid-cols-2.lg\\:grid-cols-3 {
                grid-template-columns: 1fr !important;
            }
            
            .flex.flex-wrap.gap-3 {
                flex-direction: column;
                gap: 0.75rem;
            }
            
            .flex.flex-wrap.gap-3 > * {
                width: 100%;
            }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes slideUp {
            from { transform: translateY(30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .chat-bubble { 
            max-width: 85%; padding: 1rem; border-radius: 1rem; margin-bottom: 0.75rem;
            animation: messageSlide 0.3s ease-out;
        }
        
        @keyframes messageSlide {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .chat-user { 
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            align-self: flex-end; margin-left: auto;
            color: white;
        }
        .chat-ai { 
            background: var(--glass-bg);
            border: 1px solid var(--border-color);
            align-self: flex-start;
        }
        
        .script-output { 
            background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem; 
            padding: 1.5rem; 
            font-family: 'JetBrains Mono', 'Consolas', 'Monaco', monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            font-size: 0.875rem;
            line-height: 1.6;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border: none;
            color: white;
            font-weight: 600;
            padding: 0.75rem 1.5rem;
            border-radius: 0.75rem;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(59, 130, 246, 0.4);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success), #059669);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger), #dc2626);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, var(--warning), #d97706);
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
        }
        
        .loading-spinner {
            display: inline-block;
            width: 1rem;
            height: 1rem;
            border: 2px solid transparent;
            border-top: 2px solid currentColor;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .status-connected { 
            background: var(--success);
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
        }
        .status-disconnected { 
            background: var(--danger);
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.5);
        }
        .status-connecting { 
            background: var(--warning);
            box-shadow: 0 0 10px rgba(245, 158, 11, 0.5);
        }
        
        .stat-card {
            text-align: center;
            padding: 1.5rem;
            border-radius: 1rem;
            background: var(--glass-bg);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: scale(1.05);
            background: rgba(51, 65, 85, 0.2);
        }
        
        .issue-actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }
        
        .action-btn {
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            border: none;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .ignore-btn {
            background: linear-gradient(135deg, #6b7280, #4b5563);
            color: white;
        }
        
        .ignore-btn:hover {
            background: linear-gradient(135deg, #4b5563, #374151);
            transform: translateY(-1px);
        }
        
        .chat-btn {
            background: linear-gradient(135deg, var(--accent-primary), #2563eb);
            color: white;
        }
        
        .script-btn {
            background: linear-gradient(135deg, var(--success), #059669);
            color: white;
        }
        
        input[type="text"], input[type="number"] {
            background: rgba(51, 65, 85, 0.2);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 0.75rem 1rem;
            color: var(--text-main);
            transition: all 0.3s ease;
        }
        
        input[type="text"]:focus, input[type="number"]:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
            background: rgba(51, 65, 85, 0.3);
        }
        
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 0.75rem;
            color: white;
            font-weight: 500;
            z-index: 1000;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }
        
        .toast.show {
            transform: translateX(0);
        }
        
        .toast-success {
            background: linear-gradient(135deg, var(--success), #059669);
        }
        
        .toast-error {
            background: linear-gradient(135deg, var(--danger), #dc2626);
        }
        
        .log-button {
            background: linear-gradient(135deg, #475569, #334155);
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .log-button:hover {
            background: linear-gradient(135deg, #334155, #1e293b);
            transform: translateY(-1px);
        }
        
        .clickable-chart {
            cursor: pointer;
        }
        
        .clickable-chart:hover {
            transform: scale(1.02);
        }
    </style>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body class="p-4 sm:p-6 lg:p-8">

    <div class="max-w-7xl mx-auto">
        <!-- Enhanced Header -->
        <header class="glass-card p-6 mb-8">
            <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 class="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                        Wazuh Threat Hunter Pro
                    </h1>
                    <p class="text-sm text-gray-400 mt-1">
                        Gemini AI-Powered Security Analysis
                    </p>
                    <div class="flex flex-wrap gap-4 mt-2 text-sm">
                        <span class="flex items-center gap-2">
                            <div class="w-2 h-2 rounded-full bg-blue-400"></div>
                            Last update: <span id="last-run" class="text-blue-300">Never</span>
                        </span>
                        <span class="flex items-center gap-2">
                            <div class="w-2 h-2 rounded-full bg-purple-400"></div>
                            Active API Key: <span id="active-api-key" class="text-purple-300">Key 1</span>
                        </span>
                        <span class="flex items-center gap-2">
                            <div class="w-2 h-2 rounded-full bg-green-400"></div>
                            Status: <span id="app-status" class="status-text">Initializing...</span>
                        </span>
                        <span class="flex items-center gap-2" id="countdown-container" style="display: none;">
                            <div class="w-2 h-2 rounded-full bg-yellow-400"></div>
                            Next scan in: <span id="countdown-timer" class="text-yellow-300 font-mono">--:--</span>
                        </span>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    <button id="find-more-btn" class="btn-primary btn-success">
                        <span class="flex items-center gap-2">
                            🔍 Find More Issues
                        </span>
                    </button>
                    <button id="settings-btn" class="p-3 rounded-xl bg-gray-700/50 hover:bg-gray-600/50 transition-all duration-200">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                        </svg>
                    </button>
                    <div id="status-indicator" class="w-4 h-4 rounded-full status-connecting animate-pulse" title="Connecting..."></div>
                </div>
            </div>
        </header>

        <!-- Enhanced AI Summary -->
        <div class="glass-card p-6 mb-8">
            <div class="flex items-center gap-3 mb-4">
                <div class="w-8 h-8 rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center text-white font-bold">
                    🤖
                </div>
                <h2 class="text-xl font-semibold">Gemini AI Security Analysis</h2>
            </div>
            <p id="ai-summary" class="text-gray-300 leading-relaxed">Initializing AI analysis...</p>
        </div>

        <!-- Enhanced Main Grid -->
        <div class="grid grid-cols-1 xl:grid-cols-3 gap-8">
            
            <!-- Left Column: Issues -->
            <div class="xl:col-span-2 space-y-8">
                <!-- Issues Section -->
                <div class="glass-card p-6">
                    <div class="flex items-center justify-between mb-6 security-issues-header p-2 -m-2" id="security-issues-header">
                        <h2 class="text-xl font-semibold flex items-center gap-2">
                            <span class="w-6 h-6 rounded bg-red-500/20 flex items-center justify-center text-red-400">⚠️</span>
                            Top Security Issues
                            <span id="issue-count" class="px-2 py-1 bg-red-500/20 text-red-300 rounded-lg text-sm font-medium">0</span>
                        </h2>
                        <div class="flex items-center gap-2">
                            <div id="issues-loading" class="loading-spinner hidden text-blue-400"></div>
                            <span class="text-xs text-gray-500">Click to view all</span>
                        </div>
                    </div>
                    
                    <div id="issues-container" class="space-y-4 max-h-[700px] overflow-y-auto pr-2 custom-scrollbar">
                        <!-- Top 10 AI-prioritized issues will be injected here -->
                    </div>
                </div>
                
                <!-- Chat Section -->
                <div class="glass-card p-6">
                    <div class="flex items-center gap-3 mb-4">
                        <div class="w-6 h-6 rounded bg-blue-500/20 flex items-center justify-center text-blue-400">💬</div>
                        <h2 class="text-xl font-semibold">Chat with AI Analyst</h2>
                    </div>
                    <div id="chat-container" class="max-h-[350px] overflow-y-auto mb-4 flex flex-col space-y-3 p-4 bg-black/20 rounded-xl border border-gray-700/50 custom-scrollbar">
                        <div class="chat-bubble chat-ai">
                            👋 Hello! I'm your AI security analyst. Ask me anything about your logs, threats, or security issues.
                        </div>
                    </div>
                    <div class="flex gap-3">
                        <input type="text" id="query-input" class="flex-1" placeholder="Ask about suspicious activities, specific IPs, timeframes...">
                        <button id="clear-chat-btn" class="btn-primary bg-gray-600 hover:bg-gray-700 px-4">
                            🗑️ Clear
                        </button>
                        <button id="query-btn" class="btn-primary px-6">
                            <span class="query-btn-text">Send</span>
                            <div class="loading-spinner hidden"></div>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Right Column: Stats & Visuals -->
            <div class="space-y-8">
                <!-- Enhanced Statistics -->
                <div class="glass-card p-6">
                    <h2 class="text-xl font-semibold mb-6 flex items-center gap-2">
                        <span class="w-6 h-6 rounded bg-green-500/20 flex items-center justify-center text-green-400">📊</span>
                        System Overview
                    </h2>
                    <div class="grid grid-cols-1 gap-4">
                        <div class="stat-card">
                            <div class="text-3xl font-bold text-blue-400" id="total-logs">0</div>
                            <div class="text-sm text-gray-400 mt-1">Total Logs Indexed</div>
                        </div>
                        <div class="stat-card">
                            <div class="text-3xl font-bold text-green-400" id="new-logs">0</div>
                            <div class="text-sm text-gray-400 mt-1">New Logs (Last Cycle)</div>
                        </div>
                        <div class="stat-card">
                            <div class="text-3xl font-bold text-red-400" id="anomalies">0</div>
                            <div class="text-sm text-gray-400 mt-1">Active Security Issues</div>
                        </div>
                    </div>
                </div>
                
                <!-- Enhanced Charts -->
                <div class="glass-card p-6">
                    <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <span class="w-5 h-5 rounded bg-purple-500/20 flex items-center justify-center text-purple-400">📈</span>
                        Log Activity (Last Hour)
                    </h2>
                    <div class="chart-container">
                        <canvas id="logTrendChart"></canvas>
                    </div>
                </div>
                
                <div class="glass-card p-6 clickable-chart" id="rule-chart-card">
                    <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <span class="w-5 h-5 rounded bg-yellow-500/20 flex items-center justify-center text-yellow-400">🎯</span>
                        Top Security Rules
                        <span class="text-xs text-gray-500 ml-2">Click to expand</span>
                    </h2>
                    <div class="chart-container">
                        <canvas id="ruleDistChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Notifications -->
    <div id="toast-container"></div>

    <!-- Enhanced Modals -->
    <!-- Log Detail Modal -->
    <div id="log-modal" class="modal-backdrop">
        <div class="modal-content">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold">Log Details</h2>
                <button id="close-log-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
            </div>
            <pre id="log-content" class="script-output"></pre>
        </div>
    </div>

    <!-- Issue Chat Modal -->
    <div id="issue-query-modal" class="modal-backdrop">
        <div class="modal-content">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold">Chat About Issue: <span id="issue-title" class="text-blue-400"></span></h2>
                <button id="close-issue-query-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
            </div>
            <div id="issue-chat-container" class="max-h-[400px] overflow-y-auto mb-6 flex flex-col space-y-3 p-4 bg-black/20 rounded-xl border border-gray-700/50 custom-scrollbar">
                <!-- Issue chat messages will be appended here -->
            </div>
            <div class="flex gap-3">
                <input type="text" id="issue-query-input" class="flex-1" placeholder="Ask a follow-up question...">
                <button id="issue-query-btn" class="btn-primary">Send</button>
            </div>
        </div>
    </div>

    <!-- Script Generation Modal -->
    <div id="script-modal" class="modal-backdrop">
        <div class="modal-content">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold">Diagnosis & Repair Script: <span id="script-issue-title" class="text-green-400"></span></h2>
                <button id="close-script-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
            </div>
            <div id="script-content" class="script-output mb-6">
                <div class="flex items-center gap-2">
                    <div class="loading-spinner"></div>
                    Generating comprehensive diagnosis and repair script...
                </div>
            </div>
            <div class="flex gap-3">
                <button id="copy-script-btn" class="btn-primary btn-success">📋 Copy Script</button>
                <button id="download-script-btn" class="btn-primary">💾 Download Script</button>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div id="settings-modal" class="modal-backdrop">
        <div class="modal-content">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold">Configuration Settings</h2>
                <button id="close-settings-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
            </div>
            <form id="settings-form" class="space-y-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Processing Interval (seconds)</label>
                        <input type="number" name="processing_interval" class="w-full">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Initial Scan Count</label>
                        <input type="number" name="initial_scan_count" class="w-full">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Log Batch Size</label>
                        <input type="number" name="log_batch_size" class="w-full">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Vector Search K (Query)</label>
                        <input type="number" name="search_k" class="w-full">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Vector Search K (Analysis)</label>
                        <input type="number" name="analysis_k" class="w-full">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Max Issues Displayed</label>
                        <input type="number" name="max_issues" class="w-full">
                    </div>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Gemini Max Output Tokens</label>
                    <input type="number" name="max_output_tokens" class="w-full">
                </div>
                <div class="flex gap-3 pt-4">
                    <button type="submit" class="btn-primary">💾 Save Settings</button>
                    <button type="button" id="clear-db-btn" class="btn-primary btn-danger">🗑️ Clear Database</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Rule Analysis Modal -->
    <div id="rule-analysis-modal" class="modal-backdrop">
        <div class="modal-content" style="max-width: 95vw; width: 1400px;">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold">Security Rules Analysis</h2>
                <button id="close-rule-analysis-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
            </div>
            
            <!-- Large Rule Chart -->
            <div class="glass-card p-6 mb-6">
                <h3 class="text-xl font-semibold mb-4">Rule Distribution</h3>
                <div id="modal-rule-chart-container" class="chart-container" style="height: 400px;">
                    <canvas id="modalRuleChart"></canvas>
                </div>
            </div>
            
            <!-- Filtering Controls -->
            <div class="flex flex-wrap gap-3 mb-6 p-4 bg-black/20 rounded-lg border border-gray-700/50">
                <select id="rule-severity-filter" class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
                <input type="text" id="rule-search-issues" placeholder="Search issues..." 
                       class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white flex-1 min-w-[200px]">
                <button id="rule-clear-filters" class="px-4 py-2 bg-gray-600 hover:bg-gray-500 rounded text-white">
                    Clear Filters
                </button>
                <div class="ml-auto">
                    <span id="rule-filtered-count" class="text-gray-400"></span>
                </div>
            </div>
            
            <!-- Issues Container -->
            <div id="rule-issues-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[60vh] overflow-y-auto custom-scrollbar">
                <!-- Issues will be displayed here based on rule selection -->
            </div>
        </div>
    </div>

    <!-- Full Security Issues Modal -->
    <div id="full-issues-modal" class="modal-backdrop">
        <div class="modal-content" style="max-width: 95vw; width: 1400px;">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold">All Security Issues</h2>
                <button id="close-full-issues-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
            </div>
            
            <!-- Filtering Controls for Full Modal -->
            <div class="flex flex-wrap gap-3 mb-6 p-4 bg-black/20 rounded-lg border border-gray-700/50">
                <select id="modal-severity-filter" class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                </select>
                <select id="modal-sort-issues" class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white">
                    <option value="timestamp-desc">Newest First</option>
                    <option value="timestamp-asc">Oldest First</option>
                    <option value="severity-desc">Severity (High to Low)</option>
                    <option value="severity-asc">Severity (Low to High)</option>
                    <option value="title-asc">Title (A-Z)</option>
                </select>
                <input type="text" id="modal-search-issues" placeholder="Search issues..." 
                       class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white flex-1 min-w-[200px]">
                <button id="modal-clear-filters" class="px-4 py-2 bg-gray-600 hover:bg-gray-500 rounded text-white">
                    Clear Filters
                </button>
                <div class="ml-auto flex items-center gap-2">
                    <button id="grid-view-btn" class="px-3 py-2 bg-blue-600 rounded text-white">Grid</button>
                    <button id="list-view-btn" class="px-3 py-2 bg-gray-600 rounded text-white">List</button>
                </div>
            </div>
            
            <!-- Issues Container with Grid/List toggle -->
            <div id="full-issues-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[70vh] overflow-y-auto custom-scrollbar">
                <!-- All issues will be displayed here -->
            </div>
        </div>
    </div>

    <style>
        .custom-scrollbar::-webkit-scrollbar {
            width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
            background: rgba(51, 65, 85, 0.1);
            border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: rgba(148, 163, 184, 0.3);
            border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: rgba(148, 163, 184, 0.5);
        }
        
        /* Line clamp utility for grid view */
        .line-clamp-3 {
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
        
        /* Fix chart sizing issues */
        #logTrendChart, #ruleDistChart {
            max-height: 200px !important;
            height: 200px !important;
        }
        
        #modalRuleChart {
            max-height: 400px !important;
            height: 400px !important;
        }
        
        .chart-container {
            position: relative;
            height: 200px !important;
            max-height: 200px !important;
            width: 100%;
            overflow: hidden;
        }
        
        #modal-rule-chart-container {
            height: 400px !important;
            max-height: 400px !important;
        }
        
        /* Clickable security issues header */
        .security-issues-header {
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .security-issues-header:hover {
            transform: translateY(-1px);
            background: rgba(59, 130, 246, 0.1);
            border-radius: 0.5rem;
        }
        
        /* Application status styles */
        .status-text {
            font-size: 0.875rem;
            color: #94a3b8;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        /* Additional responsive improvements */
        @media (max-width: 1024px) {
            .xl\\:col-span-2 {
                grid-column: span 1 !important;
            }
            
            .grid.grid-cols-1.xl\\:grid-cols-3 {
                grid-template-columns: 1fr !important;
            }
        }
        
        @media (max-width: 640px) {
            body {
                padding: 0.5rem;
            }
            
            .max-w-7xl {
                max-width: 100%;
            }
            
            .text-3xl {
                font-size: 1.5rem;
            }
            
            .p-6 {
                padding: 1rem;
            }
            
            .gap-8 {
                gap: 1rem;
            }
            
            .flex.flex-col.sm\\:flex-row {
                flex-direction: column !important;
                gap: 1rem;
            }
            
            .issue-actions {
                flex-direction: column;
            }
            
            .issue-actions .action-btn {
                width: 100%;
                text-align: center;
            }
        }
        
        /* Ensure charts are responsive */
        .chart-container canvas {
            max-width: 100% !important;
            height: auto !important;
        }
        
        /* Improved scrollbar for mobile */
        @media (max-width: 768px) {
            .custom-scrollbar::-webkit-scrollbar {
                width: 3px;
            }
        }
    </style>

    <script>
        // Enhanced JavaScript with better UX
        let logTrendChart, ruleDistChart, modalRuleChart;
        let currentIssueId = null;
        let issueChatHistory = [];
        let chatHistory = [];
        let countdownInterval = null;
        let lastUpdateTime = null;
        let processingInterval = 300; // Default 5 minutes
        let allIssues = []; // Store all issues for filtering
        let isGridView = true;
        let selectedRuleFilter = null;
        let dashboard_data = {};

        // Utility Functions
        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);
            
            setTimeout(() => toast.classList.add('show'), 100);
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => document.body.removeChild(toast), 300);
            }, 3000);
        }

        function renderMarkdown(text) {
            if (!text || typeof text !== 'string') return '';
            
            // Simple markdown rendering for basic formatting
            return text
                // Bold text
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                // Italic text  
                .replace(/\*(.*?)\*/g, '<em>$1</em>')
                // Inline code
                .replace(/`(.*?)`/g, '<code class="bg-gray-700 px-1 py-0.5 rounded text-sm">$1</code>')
                // Code blocks
                .replace(/```(.*?)```/gs, '<pre class="bg-gray-800 p-3 rounded mt-2 mb-2 overflow-x-auto"><code>$1</code></pre>')
                // Line breaks
                .replace(/\n/g, '<br>');
        }

        function startCountdownTimer() {
            if (countdownInterval) {
                clearInterval(countdownInterval);
            }
            
            const updateCountdown = () => {
                if (!lastUpdateTime) return;
                
                const now = Date.now();
                const nextScan = lastUpdateTime + (processingInterval * 1000);
                const timeLeft = Math.max(0, nextScan - now);
                
                if (timeLeft === 0) {
                    document.getElementById('countdown-container').style.display = 'none';
                    return;
                }
                
                const minutes = Math.floor(timeLeft / 60000);
                const seconds = Math.floor((timeLeft % 60000) / 1000);
                
                document.getElementById('countdown-timer').textContent = 
                    `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                document.getElementById('countdown-container').style.display = 'flex';
            };
            
            updateCountdown();
            countdownInterval = setInterval(updateCountdown, 1000);
        }

        function setLoadingState(button, isLoading, originalText) {
            const spinner = button.querySelector('.loading-spinner');
            const text = button.querySelector('.query-btn-text') || button;
            
            if (isLoading) {
                button.disabled = true;
                if (spinner) spinner.classList.remove('hidden');
                if (text !== button) text.textContent = 'Thinking...';
                else button.innerHTML = '<div class="loading-spinner"></div>';
            } else {
                button.disabled = false;
                if (spinner) spinner.classList.add('hidden');
                if (text !== button) text.textContent = originalText;
                else button.textContent = originalText;
            }
        }

        function initializeCharts() {
            const logTrendCanvas = document.getElementById('logTrendChart');
            const ruleDistCanvas = document.getElementById('ruleDistChart');
            
            if (!logTrendCanvas || !ruleDistCanvas) {
                console.error('Chart canvas elements not found');
                return;
            }
            
            const chartOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { 
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(30, 41, 59, 0.9)',
                        titleColor: '#f8fafc',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(148, 163, 184, 0.2)',
                        borderWidth: 1,
                        cornerRadius: 8,
                    }
                },
                scales: {
                    x: { 
                        ticks: { color: '#94a3b8' }, 
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        border: { color: 'rgba(148, 163, 184, 0.2)' }
                    },
                    y: { 
                        ticks: { color: '#94a3b8' }, 
                        grid: { color: 'rgba(148, 163, 184, 0.1)' },
                        border: { color: 'rgba(148, 163, 184, 0.2)' }
                    }
                }
            };

            try {
                const trendCtx = logTrendCanvas.getContext('2d');
                logTrendChart = new Chart(trendCtx, {
                    type: 'line',
                    data: { 
                        labels: [], 
                        datasets: [{ 
                            label: 'Logs per Minute', 
                            data: [], 
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.4,
                            fill: true,
                            pointBackgroundColor: '#3b82f6',
                            pointBorderColor: '#1e40af',
                            pointRadius: 4,
                            pointHoverRadius: 6
                        }] 
                    },
                    options: { 
                        ...chartOptions,
                        height: 200,
                        scales: { 
                            ...chartOptions.scales, 
                            x: { 
                                ...chartOptions.scales.x,
                                type: 'category'  // Changed from 'time' to fix display issues
                            } 
                        } 
                    }
                });
                console.log('Log trend chart initialized');
            } catch (error) {
                console.error('Error initializing log trend chart:', error);
            }

            try {
                const ruleCtx = ruleDistCanvas.getContext('2d');
                ruleDistChart = new Chart(ruleCtx, {
                    type: 'doughnut',
                    data: { 
                        labels: [], 
                        datasets: [{ 
                            label: 'Rule Events', 
                            data: [], 
                            backgroundColor: [
                                '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                                '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1'
                            ],
                            borderWidth: 2,
                            borderColor: 'rgba(30, 41, 59, 0.8)'
                        }] 
                    },
                    options: { 
                        ...chartOptions,
                        height: 200,
                        onClick: (event, elements) => {
                            if (elements.length > 0) {
                                const index = elements[0].index;
                                const ruleName = ruleDistChart.data.labels[index];
                                openRuleAnalysisModal(ruleName);
                            }
                        },
                        plugins: { 
                            legend: { 
                                position: 'bottom', 
                                labels: { 
                                    color: '#cbd5e1',
                                    usePointStyle: true,
                                    padding: 15,
                                    font: { size: 11 }
                                } 
                            },
                            tooltip: {
                                backgroundColor: 'rgba(30, 41, 59, 0.9)',
                                titleColor: '#f8fafc',
                                bodyColor: '#cbd5e1',
                                borderColor: 'rgba(148, 163, 184, 0.2)',
                                borderWidth: 1,
                                cornerRadius: 8,
                                callbacks: {
                                    afterLabel: function(context) {
                                        return 'Click to view details';
                                    }
                                }
                            }
                        } 
                    }
                });
                console.log('Rule distribution chart initialized');
            } catch (error) {
                console.error('Error initializing rule distribution chart:', error);
            }
        }

        function openRuleAnalysisModal(selectedRule = null) {
            const modal = document.getElementById('rule-analysis-modal');
            selectedRuleFilter = selectedRule;
            
            // Update the large chart in the modal
            updateRuleAnalysisModal();
            
            modal.style.display = 'flex';
        }

        function updateRuleAnalysisModal() {
            const container = document.getElementById('rule-issues-container');
            
            // Initialize or update the large chart
            if (!modalRuleChart) {
                const ctx = document.getElementById('modalRuleChart').getContext('2d');
                
                modalRuleChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: { 
                        labels: [], 
                        datasets: [{ 
                            label: 'Rule Events', 
                            data: [], 
                            backgroundColor: [
                                '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                                '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1',
                                '#14b8a6', '#a855f7', '#f59e0b', '#ef4444', '#3b82f6'
                            ],
                            borderWidth: 2,
                            borderColor: 'rgba(30, 41, 59, 0.8)'
                        }] 
                    },
                    options: { 
                        responsive: true,
                        maintainAspectRatio: false,
                        height: 400,
                        onClick: (event, elements) => {
                            if (elements.length > 0) {
                                const index = elements[0].index;
                                const ruleName = modalRuleChart.data.labels[index];
                                selectedRuleFilter = ruleName;
                                filterRuleIssues();
                            }
                        },
                        plugins: { 
                            legend: { 
                                position: 'bottom', 
                                labels: { 
                                    color: '#cbd5e1',
                                    usePointStyle: true,
                                    padding: 15,
                                    font: { size: 12 }
                                } 
                            },
                            tooltip: {
                                backgroundColor: 'rgba(30, 41, 59, 0.9)',
                                titleColor: '#f8fafc',
                                bodyColor: '#cbd5e1',
                                borderColor: 'rgba(148, 163, 184, 0.2)',
                                borderWidth: 1,
                                cornerRadius: 8,
                                callbacks: {
                                    afterLabel: function(context) {
                                        return 'Click to filter issues by this rule';
                                    }
                                }
                            }
                        } 
                    }
                });
            }
            
            // Update chart data
            const ruleData = dashboard_data.rule_distribution || {};
            const sortedRules = Object.entries(ruleData)
                .sort(([,a],[,b]) => b-a)
                .slice(0, 15); // Show top 15 in the modal
            
            modalRuleChart.data.labels = sortedRules.map(([rule]) => rule);
            modalRuleChart.data.datasets[0].data = sortedRules.map(([,count]) => count);
            modalRuleChart.update();
            
            // Filter issues based on selected rule
            filterRuleIssues();
        }

        function filterRuleIssues() {
            const severityFilter = document.getElementById('rule-severity-filter').value;
            const searchTerm = document.getElementById('rule-search-issues').value.toLowerCase();
            const container = document.getElementById('rule-issues-container');
            
            let filteredIssues = [...allIssues];
            
            // Filter by rule if one is selected
            if (selectedRuleFilter) {
                filteredIssues = filteredIssues.filter(issue => {
                    return issue.summary.toLowerCase().includes(selectedRuleFilter.toLowerCase()) ||
                           issue.title.toLowerCase().includes(selectedRuleFilter.toLowerCase()) ||
                           issue.recommendation.toLowerCase().includes(selectedRuleFilter.toLowerCase());
                });
            }
            
            // Apply severity filter
            if (severityFilter) {
                filteredIssues = filteredIssues.filter(issue => issue.severity === severityFilter);
            }
            
            // Apply search filter
            if (searchTerm) {
                filteredIssues = filteredIssues.filter(issue => 
                    issue.title.toLowerCase().includes(searchTerm) ||
                    issue.summary.toLowerCase().includes(searchTerm)
                );
            }
            
            // Update counter
            document.getElementById('rule-filtered-count').textContent = 
                `Showing ${filteredIssues.length} of ${allIssues.length} issues`;
            
            // Display issues
            displayRuleIssues(filteredIssues);
        }

        function displayRuleIssues(issues) {
            const container = document.getElementById('rule-issues-container');
            container.innerHTML = '';
            
            if (issues.length === 0) {
                container.innerHTML = `
                    <div class="col-span-full text-center py-12">
                        <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-blue-500/20 flex items-center justify-center">
                            <span class="text-2xl">🔍</span>
                        </div>
                        <p class="text-gray-400 text-lg">${selectedRuleFilter ? `No issues found for rule: ${selectedRuleFilter}` : 'No issues match your filters'}</p>
                        <p class="text-gray-500 text-sm mt-2">Try adjusting your search criteria</p>
                    </div>
                `;
                return;
            }

            issues.forEach((issue, index) => {
                const issueEl = document.createElement('div');
                issueEl.className = `glass-card p-4 severity-${issue.severity} h-fit`;
                
                const severityIcons = {
                    'Critical': '🚨',
                    'High': '⚠️',
                    'Medium': '🔶',
                    'Low': 'ℹ️'
                };
                
                const severityColors = {
                    'Critical': 'text-red-400 bg-red-500/20',
                    'High': 'text-orange-400 bg-orange-500/20',
                    'Medium': 'text-yellow-400 bg-yellow-500/20',
                    'Low': 'text-green-400 bg-green-500/20'
                };

                const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                    ? issue.related_logs.slice(0, 3).map(logId => 
                        `<button class="log-button text-xs" data-log-id="${logId}" title="Click to view log details">
                            ${logId.substring(0, 6)}...
                        </button>`
                      ).join('')
                    : '<span class="text-gray-500 text-xs">No logs</span>';

                issueEl.innerHTML = `
                    <div class="flex justify-between items-start mb-3">
                        <div class="flex items-center gap-2">
                            <div class="w-6 h-6 rounded ${severityColors[issue.severity]} flex items-center justify-center text-sm">
                                ${severityIcons[issue.severity]}
                            </div>
                            <div>
                                <span class="text-xs font-bold uppercase ${severityColors[issue.severity].split(' ')[0]} block">
                                    ${issue.severity}
                                </span>
                                <h3 class="font-bold text-sm text-white leading-tight">${issue.title}</h3>
                            </div>
                        </div>
                        <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                            ${new Date(issue.timestamp).toLocaleTimeString()}
                        </span>
                    </div>
                    
                    <div class="text-gray-300 mb-3 text-sm leading-relaxed line-clamp-3">${renderMarkdown(issue.summary)}</div>
                    
                    <details class="mb-3">
                        <summary class="cursor-pointer text-blue-400 hover:text-blue-300 text-sm mb-2">
                            📋 Details & Logs
                        </summary>
                        <div class="mt-2 p-3 bg-black/20 rounded border border-gray-700/50">
                            <div class="mb-3">
                                <h4 class="font-semibold text-white text-sm mb-1">🎯 Actions:</h4>
                                <div class="text-gray-300 text-sm">${renderMarkdown(issue.recommendation.substring(0, 200))}${issue.recommendation.length > 200 ? '...' : ''}</div>
                            </div>
                            <div>
                                <h4 class="font-semibold text-white text-sm mb-1">📄 Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                                <div class="flex flex-wrap gap-1">
                                    ${relatedLogsHtml}
                                </div>
                            </div>
                        </div>
                    </details>
                    
                    <div class="flex gap-1 flex-wrap">
                        <button class="action-btn ignore-btn text-xs py-1 px-2" data-issue-id="${issue.id}">
                            🗑️ Ignore
                        </button>
                        <button class="action-btn chat-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${issue.title}">
                            💬 Chat
                        </button>
                        <button class="action-btn script-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${issue.title}">
                            🔧 Script
                        </button>
                    </div>
                `;
                container.appendChild(issueEl);
            });
        }

        async function updateUI(data) {
            dashboard_data = data;
            
            // Update header info
            document.getElementById('last-run').textContent = data.last_run ? 
                new Date(data.last_run).toLocaleString() : 'Never';
            document.getElementById('ai-summary').innerHTML = renderMarkdown(data.summary);
            document.getElementById('active-api-key').textContent = `Key ${(data.active_api_key_index || 0) + 1}`;
            
            // Update application status and handle countdown
            const status = data.status || 'Unknown';
            document.getElementById('app-status').textContent = status;
            
            // Update processing interval and start countdown if idle/ready
            if (data.settings && data.settings.processing_interval) {
                processingInterval = data.settings.processing_interval;
            }
            
            if (data.last_run) {
                lastUpdateTime = new Date(data.last_run).getTime();
                if (status === 'Ready' || status === 'Idle') {
                    startCountdownTimer();
                } else {
                    document.getElementById('countdown-container').style.display = 'none';
                }
            }
            
            // Store all issues for filtering
            allIssues = data.issues || [];
            
            // Update statistics with animations
            updateStatWithAnimation('total-logs', data.stats.total_logs);
            updateStatWithAnimation('new-logs', data.stats.new_logs);
            updateStatWithAnimation('anomalies', data.stats.anomalies);
            
            // Sort issues by timestamp (most recent first) and show first 10 in widget
            const sortedIssues = [...allIssues].sort((a, b) => 
                new Date(b.timestamp) - new Date(a.timestamp)
            );
            const displayIssues = sortedIssues.slice(0, 10);
            
            updateIssuesDisplay(displayIssues, false); // false = no filtering controls in main widget

            // Update charts
            updateCharts(data);
        }

        function updateStatWithAnimation(elementId, newValue) {
            const element = document.getElementById(elementId);
            const currentValue = parseInt(element.textContent.replace(/,/g, '')) || 0;
            
            if (currentValue !== newValue) {
                element.style.transform = 'scale(1.1)';
                setTimeout(() => {
                    element.textContent = newValue.toLocaleString();
                    element.style.transform = 'scale(1)';
                }, 150);
            }
        }

        function updateIssuesDisplay(issues, showFilters = true) {
            const container = document.getElementById('issues-container');
            
            if (!container) {
                console.error('Issues container not found');
                return;
            }
            
            container.innerHTML = '';
            
            if (!issues || issues.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-12">
                        <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center">
                            <span class="text-2xl">✅</span>
                        </div>
                        <p class="text-gray-400 text-lg">No security issues found</p>
                        <p class="text-gray-500 text-sm mt-2">Your systems appear secure</p>
                    </div>
                `;
                return;
            }

            console.log(`Displaying ${issues.length} issues in main widget`);

            issues.forEach((issue, index) => {
                try {
                    const issueEl = document.createElement('div');
                    issueEl.className = `glass-card p-6 severity-${issue.severity || 'Low'}`;
                    issueEl.style.animationDelay = `${index * 0.1}s`;
                    
                    const severityIcons = {
                        'Critical': '🚨',
                        'High': '⚠️',
                        'Medium': '🔶',
                        'Low': 'ℹ️'
                    };
                    
                    const severityColors = {
                        'Critical': 'text-red-400 bg-red-500/20',
                        'High': 'text-orange-400 bg-orange-500/20',
                        'Medium': 'text-yellow-400 bg-yellow-500/20',
                        'Low': 'text-green-400 bg-green-500/20'
                    };

                    // Format related logs with proper display - Fixed to ensure logs are shown
                    const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                        ? issue.related_logs.map((logId, idx) => {
                            // Handle both string IDs and objects
                            const actualLogId = typeof logId === 'string' ? logId : (logId.id || logId.sha256 || String(logId));
                            return `<button class="log-button" data-log-id="${actualLogId}" title="Click to view log details">
                                Log ${idx + 1}: ${actualLogId.substring(0, 8)}...
                            </button>`;
                          }).join('')
                        : '<span class="text-gray-500 text-sm">No related logs available</span>';

                    const severity = issue.severity || 'Low';
                    const title = escapeHtml(issue.title || 'Untitled Issue');
                    const summary = issue.summary || 'No summary available';
                    const recommendation = issue.recommendation || 'No recommendations available';
                    const timestamp = issue.timestamp ? new Date(issue.timestamp).toLocaleTimeString() : 'Unknown time';

                    issueEl.innerHTML = `
                        <div class="flex justify-between items-start mb-4">
                            <div class="flex items-center gap-3">
                                <div class="w-8 h-8 rounded-lg ${severityColors[severity]} flex items-center justify-center">
                                    ${severityIcons[severity]}
                                </div>
                                <div>
                                    <span class="text-xs font-bold uppercase ${severityColors[severity].split(' ')[0]} block mb-1">
                                        ${severity} Severity
                                    </span>
                                    <h3 class="font-bold text-lg text-white">${title}</h3>
                                </div>
                            </div>
                            <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                                ${timestamp}
                            </span>
                        </div>
                        
                        <div class="text-gray-300 mb-4 leading-relaxed">${renderMarkdown(summary)}</div>
                        
                        <details class="mb-4">
                            <summary class="cursor-pointer text-blue-400 hover:text-blue-300 font-medium mb-2" onclick="event.stopPropagation();">
                                📋 View Recommendations & Related Logs
                            </summary>
                            <div class="mt-3 p-4 bg-black/20 rounded-lg border border-gray-700/50" onclick="event.stopPropagation();">
                                <div class="mb-4">
                                    <h4 class="font-semibold text-white mb-2">🎯 Recommended Actions:</h4>
                                    <div class="text-gray-300 whitespace-pre-wrap leading-relaxed">${renderMarkdown(recommendation)}</div>
                                </div>
                                <div>
                                    <h4 class="font-semibold text-white mb-2">📄 Related Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                                    <div class="flex flex-wrap gap-2">
                                        ${relatedLogsHtml}
                                    </div>
                                </div>
                            </div>
                        </details>
                        
                        <div class="issue-actions">
                            <button class="action-btn ignore-btn" data-issue-id="${issue.id || ''}">
                                🗑️ Ignore Issue
                            </button>
                            <button class="action-btn chat-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                                💬 Chat About This
                            </button>
                            <button class="action-btn script-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                                🔧 Generate Fix Script
                            </button>
                        </div>
                    `;
                    container.appendChild(issueEl);
                } catch (error) {
                    console.error(`Error rendering issue ${index}:`, error, issue);
                }
            });
            
            // Update issue count to show total issues
            const countElement = document.getElementById('issue-count');
            if (countElement) {
                countElement.textContent = allIssues.length;
            }
        }

        function updateCharts(data) {
            // Update trend chart with proper data formatting
            if (data.log_trend && data.log_trend.length > 0) {
                const trendLabels = data.log_trend.map(d => d.time);
                const trendData = data.log_trend.map(d => d.count);
                
                logTrendChart.data.labels = trendLabels;
                logTrendChart.data.datasets[0].data = trendData;
            } else {
                // Show empty state with sample data points
                logTrendChart.data.labels = ['Now-60min', 'Now-45min', 'Now-30min', 'Now-15min', 'Now'];
                logTrendChart.data.datasets[0].data = [0, 0, 0, 0, 0];
            }
            
            logTrendChart.options.maintainAspectRatio = false;
            logTrendChart.options.responsive = true;
            logTrendChart.update('none');

            // Update rule distribution chart with bounds checking
            if (data.rule_distribution && Object.keys(data.rule_distribution).length > 0) {
                const sortedRules = Object.entries(data.rule_distribution)
                    .sort(([,a],[,b]) => b-a)
                    .slice(0, 10);
                    
                ruleDistChart.data.labels = sortedRules.map(([rule]) => 
                    rule.length > 30 ? rule.substring(0, 27) + '...' : rule
                );
                ruleDistChart.data.datasets[0].data = sortedRules.map(([,count]) => count);
            } else {
                // Show empty state
                ruleDistChart.data.labels = ['No data available'];
                ruleDistChart.data.datasets[0].data = [1];
            }
            
            ruleDistChart.options.maintainAspectRatio = false;
            ruleDistChart.options.responsive = true;
            ruleDistChart.update('none');
            
            // Update modal chart if it exists
            if (modalRuleChart) {
                updateRuleAnalysisModal();
            }
        }

        async function fetchData() {
            const statusIndicator = document.getElementById('status-indicator');
            
            try {
                console.log('Fetching dashboard data...');
                statusIndicator.className = 'w-4 h-4 rounded-full status-connecting animate-pulse';
                statusIndicator.title = 'Connecting...';
                
                const response = await fetch('/api/dashboard');
                console.log('Dashboard API response status:', response.status);
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                console.log('Dashboard data received:', {
                    issueCount: data.issues ? data.issues.length : 0,
                    totalLogs: data.stats ? data.stats.total_logs : 0,
                    status: data.status
                });
                
                await updateUI(data);
                statusIndicator.className = 'w-4 h-4 rounded-full status-connected';
                statusIndicator.title = `Connected. Last update: ${new Date(data.last_run || Date.now()).toLocaleString()}`;
                
            } catch (error) {
                console.error("Failed to fetch dashboard data:", error);
                
                // Update UI with error state
                document.getElementById('ai-summary').textContent = 'Error: Could not connect to the backend service. Please check if the server is running.';
                statusIndicator.className = 'w-4 h-4 rounded-full status-disconnected';
                statusIndicator.title = `Connection failed: ${error.message}`;
                
                // Show error in issues container
                const issuesContainer = document.getElementById('issues-container');
                if (issuesContainer) {
                    issuesContainer.innerHTML = `
                        <div class="text-center py-12">
                            <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-red-500/20 flex items-center justify-center">
                                <span class="text-2xl">❌</span>
                            </div>
                            <p class="text-red-400 text-lg">Connection Failed</p>
                            <p class="text-gray-500 text-sm mt-2">Unable to fetch security data from server</p>
                            <button onclick="fetchData()" class="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                                Retry Connection
                            </button>
                        </div>
                    `;
                }
                
                showToast('Failed to fetch dashboard data. Check console for details.', 'error');
            }
        }

        async function triggerAnalysis() {
            const btn = document.getElementById('find-more-btn');
            const originalText = btn.textContent;
            
            try {
                setLoadingState(btn, true, originalText);
                document.getElementById('issues-loading').classList.remove('hidden');
                
                const response = await fetch('/api/analyze', { method: 'POST' });
                if (!response.ok) throw new Error('Failed to trigger analysis');
                
                showToast('Analysis triggered successfully!');
                fetchData();
            } catch (error) {
                console.error("Failed to trigger analysis:", error);
                showToast('Failed to trigger analysis', 'error');
            } finally {
                setLoadingState(btn, false, '🔍 Find More Issues');
                document.getElementById('issues-loading').classList.add('hidden');
            }
        }

        async function ignoreIssue(issueId) {
            try {
                const response = await fetch(`/api/issues/${issueId}/ignore`, { method: 'POST' });
                if (!response.ok) throw new Error('Failed to ignore issue');
                
                showToast('Issue ignored successfully');
                fetchData();
            } catch (error) {
                console.error("Failed to ignore issue:", error);
                showToast('Failed to ignore issue', 'error');
            }
        }

        async function openIssueQueryModal(issueId, issueTitle) {
            currentIssueId = issueId;
            issueChatHistory = [];
            document.getElementById('issue-title').textContent = issueTitle;
            const issueChatContainer = document.getElementById('issue-chat-container');
            issueChatContainer.innerHTML = `
                <div class="chat-bubble chat-ai">
                    👋 I'm here to help you understand and resolve this security issue. What would you like to know?
                </div>
            `;
            document.getElementById('issue-query-modal').style.display = 'flex';
            document.getElementById('issue-query-input').focus();
        }

        async function handleIssueQuery() {
            const query = document.getElementById('issue-query-input').value.trim();
            if (!query || !currentIssueId) return;
            
            const btn = document.getElementById('issue-query-btn');
            const issueChatContainer = document.getElementById('issue-chat-container');
            
            appendChatMessage(issueChatContainer, query, 'chat-user');
            document.getElementById('issue-query-input').value = '';
            
            setLoadingState(btn, true, 'Send');
            
            try {
                const response = await fetch(`/api/issues/${currentIssueId}/query`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: query, history: issueChatHistory })
                });
                const result = await response.json();
                appendChatMessage(issueChatContainer, result.answer, 'chat-ai');
                issueChatHistory.push({ user: query, ai: result.answer });
            } catch (error) {
                appendChatMessage(issueChatContainer, `❌ Error: ${error.message}`, 'chat-ai');
            } finally {
                setLoadingState(btn, false, 'Send');
                issueChatContainer.scrollTop = issueChatContainer.scrollHeight;
            }
        }

        async function handleQuery() {
            const query = document.getElementById('query-input').value.trim();
            if (!query) return;
            
            const btn = document.getElementById('query-btn');
            const chatContainer = document.getElementById('chat-container');
            
            appendChatMessage(chatContainer, query, 'chat-user');
            document.getElementById('query-input').value = '';
            
            setChatButtonStatus(btn, 'Starting analysis...');
            
            try {
                // Step 1: Initial analysis and planning
                setChatButtonStatus(btn, 'Analyzing query...');
                const response = await fetch('/api/chat/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        query: query, 
                        history: chatHistory.slice(-3) // Last 3 exchanges
                    })
                });
                
                if (!response.ok) {
                    throw new Error(`Analysis failed: ${response.status}`);
                }
                
                const analysisResult = await response.json();
                
                // Step 2: Execute the planned searches and get final response
                setChatButtonStatus(btn, 'Searching logs...');
                const finalResponse = await fetch('/api/chat/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        query: query,
                        analysis: analysisResult,
                        history: chatHistory.slice(-3)
                    })
                });
                
                if (!finalResponse.ok) {
                    throw new Error(`Execution failed: ${finalResponse.status}`);
                }
                
                const result = await finalResponse.json();
                appendChatMessage(chatContainer, result.answer, 'chat-ai');
                chatHistory.push({ user: query, ai: result.answer });
                
            } catch (error) {
                console.error('Chat error:', error);
                appendChatMessage(chatContainer, `❌ Error: ${error.message}`, 'chat-ai');
            } finally {
                setChatButtonStatus(btn, 'idle');
                chatContainer.scrollTop = chatContainer.scrollHeight;
            }
        }

        function clearChat() {
            const chatContainer = document.getElementById('chat-container');
            chatHistory = [];
            chatContainer.innerHTML = `
                <div class="chat-bubble chat-ai">
                    👋 Hello! I'm your AI security analyst. Ask me anything about your logs, threats, or security issues.
                </div>
            `;
        }

        function appendChatMessage(container, message, className) {
            const bubble = document.createElement('div');
            bubble.className = `chat-bubble ${className} text-white whitespace-pre-wrap`;
            
            if (className === 'chat-ai') {
                bubble.innerHTML = renderMarkdown(message);
            } else {
                bubble.textContent = message;
            }
            
            container.appendChild(bubble);
            container.scrollTop = container.scrollHeight;
        }

        function setChatButtonStatus(button, status) {
            const spinner = button.querySelector('.loading-spinner');
            const text = button.querySelector('.query-btn-text');
            
            if (status === 'idle') {
                button.disabled = false;
                if (spinner) spinner.classList.add('hidden');
                text.textContent = 'Send';
            } else {
                button.disabled = true;
                if (spinner) spinner.classList.remove('hidden');
                text.textContent = status;
            }
        }

        async function generateScript(issueId, issueTitle) {
            document.getElementById('script-issue-title').textContent = issueTitle;
            document.getElementById('script-content').innerHTML = `
                <div class="flex items-center gap-2 text-blue-400">
                    <div class="loading-spinner"></div>
                    Generating comprehensive diagnosis and repair script...
                </div>
            `;
            document.getElementById('script-modal').style.display = 'flex';
            
            try {
                const response = await fetch(`/api/issues/${issueId}/generate-script`, { method: 'POST' });
                if (!response.ok) throw new Error('Failed to generate script');
                const result = await response.json();
                document.getElementById('script-content').textContent = result.script;
                showToast('Script generated successfully!');
            } catch (error) {
                document.getElementById('script-content').textContent = `❌ Error generating script: ${error.message}`;
                showToast('Failed to generate script', 'error');
            }
        }

        function openFullIssuesModal(issues) {
            const modal = document.getElementById('full-issues-modal');
            const container = document.getElementById('full-issues-container');
            allIssues = issues; // Store for filtering
            
            displayModalIssues(issues);
            modal.style.display = 'flex';
        }

        function displayModalIssues(issues) {
            const container = document.getElementById('full-issues-container');
            
            if (!container) {
                console.error('Full issues container not found');
                return;
            }
            
            container.innerHTML = '';
            
            if (!issues || issues.length === 0) {
                container.innerHTML = `
                    <div class="col-span-full text-center py-12">
                        <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center">
                            <span class="text-2xl">✅</span>
                        </div>
                        <p class="text-gray-400 text-lg">No security issues match your filters</p>
                        <p class="text-gray-500 text-sm mt-2">Try adjusting your search criteria</p>
                    </div>
                `;
                return;
            }

            // Update grid/list classes
            if (isGridView) {
                container.className = 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[70vh] overflow-y-auto custom-scrollbar';
            } else {
                container.className = 'space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar';
            }

            // Limit issues to prevent performance issues
            const issuesToDisplay = issues.slice(0, 100); // Show max 100 issues in modal
            
            console.log(`Displaying ${issuesToDisplay.length} issues in modal`);

            issuesToDisplay.forEach((issue, index) => {
                try {
                    const issueEl = document.createElement('div');
                    issueEl.className = `glass-card p-4 severity-${issue.severity} ${isGridView ? 'h-fit' : ''}`;
                    
                    const severityIcons = {
                        'Critical': '🚨',
                        'High': '⚠️',
                        'Medium': '🔶',
                        'Low': 'ℹ️'
                    };
                    
                    const severityColors = {
                        'Critical': 'text-red-400 bg-red-500/20',
                        'High': 'text-orange-400 bg-orange-500/20',
                        'Medium': 'text-yellow-400 bg-yellow-500/20',
                        'Low': 'text-green-400 bg-green-500/20'
                    };

                    const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                        ? issue.related_logs.slice(0, 3).map((logId, idx) => {
                            // Handle both string IDs and objects
                            const actualLogId = typeof logId === 'string' ? logId : (logId.id || logId.sha256 || String(logId));
                            return `<button class="log-button text-xs" data-log-id="${actualLogId}" title="Click to view log details">
                                ${actualLogId.substring(0, 6)}...
                            </button>`;
                          }).join('')
                        : '<span class="text-gray-500 text-xs">No logs</span>';

                    issueEl.innerHTML = `
                        <div class="flex justify-between items-start mb-3">
                            <div class="flex items-center gap-2">
                                <div class="w-6 h-6 rounded ${severityColors[issue.severity]} flex items-center justify-center text-sm">
                                    ${severityIcons[issue.severity]}
                                </div>
                                <div>
                                    <span class="text-xs font-bold uppercase ${severityColors[issue.severity].split(' ')[0]} block">
                                        ${issue.severity}
                                    </span>
                                    <h3 class="font-bold text-sm text-white leading-tight">${escapeHtml(issue.title || 'Untitled Issue')}</h3>
                                </div>
                            </div>
                            <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                                ${new Date(issue.timestamp).toLocaleTimeString()}
                            </span>
                        </div>
                        
                        <div class="text-gray-300 mb-3 text-sm leading-relaxed ${isGridView ? 'line-clamp-3' : ''}">${renderMarkdown(issue.summary || 'No summary available')}</div>
                        
                        <details class="mb-3">
                            <summary class="cursor-pointer text-blue-400 hover:text-blue-300 text-sm mb-2" onclick="event.stopPropagation();">
                                📋 Details & Logs
                            </summary>
                            <div class="mt-2 p-3 bg-black/20 rounded border border-gray-700/50" onclick="event.stopPropagation();">
                                <div class="mb-3">
                                    <h4 class="font-semibold text-white text-sm mb-1">🎯 Actions:</h4>
                                    <div class="text-gray-300 text-sm">${renderMarkdown((issue.recommendation || 'No recommendations available').substring(0, 200))}${(issue.recommendation && issue.recommendation.length > 200) ? '...' : ''}</div>
                                </div>
                                <div>
                                    <h4 class="font-semibold text-white text-sm mb-1">📄 Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                                    <div class="flex flex-wrap gap-1">
                                        ${relatedLogsHtml}
                                    </div>
                                </div>
                            </div>
                        </details>
                        
                        <div class="flex gap-1 flex-wrap">
                            <button class="action-btn ignore-btn text-xs py-1 px-2" data-issue-id="${issue.id}">
                                🗑️ Ignore
                            </button>
                            <button class="action-btn chat-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${escapeHtml(issue.title || '')}">
                                💬 Chat
                            </button>
                            <button class="action-btn script-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${escapeHtml(issue.title || '')}">
                                🔧 Script
                            </button>
                        </div>
                    `;
                    container.appendChild(issueEl);
                } catch (error) {
                    console.error(`Error rendering issue ${index}:`, error, issue);
                }
            });
            
            console.log(`Successfully displayed ${issuesToDisplay.length} issues in modal`);
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function applyModalFilters() {
            const severityFilter = document.getElementById('modal-severity-filter').value;
            const sortBy = document.getElementById('modal-sort-issues').value;
            const searchTerm = document.getElementById('modal-search-issues').value.toLowerCase();
            
            let filteredIssues = [...allIssues];
            
            // Apply severity filter
            if (severityFilter) {
                filteredIssues = filteredIssues.filter(issue => issue.severity === severityFilter);
            }
            
            // Apply search filter
            if (searchTerm) {
                filteredIssues = filteredIssues.filter(issue => 
                    issue.title.toLowerCase().includes(searchTerm) ||
                    issue.summary.toLowerCase().includes(searchTerm)
                );
            }
            
            // Apply sorting
            filteredIssues.sort((a, b) => {
                switch(sortBy) {
                    case 'timestamp-desc':
                        return new Date(b.timestamp) - new Date(a.timestamp);
                    case 'timestamp-asc':
                        return new Date(a.timestamp) - new Date(b.timestamp);
                    case 'severity-desc':
                        const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
                        return severityOrder[b.severity] - severityOrder[a.severity];
                    case 'severity-asc':
                        const severityOrderAsc = { Critical: 4, High: 3, Medium: 2, Low: 1 };
                        return severityOrderAsc[a.severity] - severityOrderAsc[b.severity];
                    case 'title-asc':
                        return a.title.localeCompare(b.title);
                    default:
                        return 0;
                }
            });
            
            displayModalIssues(filteredIssues);
        }

        // Modal Functions
        const logModal = document.getElementById('log-modal');
        const issueQueryModal = document.getElementById('issue-query-modal');
        const settingsModal = document.getElementById('settings-modal');
        const scriptModal = document.getElementById('script-modal');
        const fullIssuesModal = document.getElementById('full-issues-modal');
        const ruleAnalysisModal = document.getElementById('rule-analysis-modal');

        async function showLogModal(logId) {
            const logContent = document.getElementById('log-content');
            logContent.innerHTML = '<div class="loading-spinner"></div> Loading log details...';
            logModal.style.display = 'flex';
            
            try {
                const res = await fetch(`/api/logs/${logId}`);
                if (!res.ok) throw new Error(`Failed to fetch log ${logId}`);
                const data = await res.json();
                logContent.textContent = JSON.stringify(data, null, 2);
            } catch (e) {
                logContent.textContent = `❌ Error: ${e.message}`;
            }
        }

        // Event Listeners
        document.addEventListener('click', (event) => {
            // Log buttons
            if (event.target.matches('.log-button')) {
                showLogModal(event.target.dataset.logId);
            }
            
            // Issue action buttons
            if (event.target.matches('.ignore-btn')) {
                if (confirm('Are you sure you want to ignore this security issue?')) {
                    ignoreIssue(event.target.dataset.issueId);
                }
            }
            
            if (event.target.matches('.chat-btn')) {
                openIssueQueryModal(event.target.dataset.issueId, event.target.dataset.issueTitle);
            }
            
            if (event.target.matches('.script-btn')) {
                generateScript(event.target.dataset.issueId, event.target.dataset.issueTitle);
            }
        });

        // Modal close handlers
        document.getElementById('close-log-modal-btn').onclick = () => logModal.style.display = 'none';
        document.getElementById('close-issue-query-modal-btn').onclick = () => issueQueryModal.style.display = 'none';
        document.getElementById('close-script-modal-btn').onclick = () => scriptModal.style.display = 'none';
        document.getElementById('close-settings-modal-btn').onclick = () => settingsModal.style.display = 'none';
        document.getElementById('close-full-issues-modal-btn').onclick = () => fullIssuesModal.style.display = 'none';
        document.getElementById('close-rule-analysis-modal-btn').onclick = () => {
            ruleAnalysisModal.style.display = 'none';
            selectedRuleFilter = null;
        };

        // Click outside to close modals
        window.onclick = (event) => {
            if (event.target == logModal) logModal.style.display = 'none';
            if (event.target == issueQueryModal) issueQueryModal.style.display = 'none';
            if (event.target == settingsModal) settingsModal.style.display = 'none';
            if (event.target == scriptModal) scriptModal.style.display = 'none';
            if (event.target == fullIssuesModal) fullIssuesModal.style.display = 'none';
            if (event.target == ruleAnalysisModal) {
                ruleAnalysisModal.style.display = 'none';
                selectedRuleFilter = null;
            }
        };

        // Rule chart click handler
        document.getElementById('rule-chart-card').addEventListener('click', () => {
            openRuleAnalysisModal();
        });

        // Security issues header click handler
        document.getElementById('security-issues-header').addEventListener('click', async () => {
            console.log('Security issues header clicked');
            
            try {
                // Use existing issues data if available, otherwise fetch fresh data
                let issuesToShow = allIssues;
                
                if (!issuesToShow || issuesToShow.length === 0) {
                    console.log('No cached issues, fetching fresh data...');
                    const response = await fetch('/api/dashboard');
                    if (response.ok) {
                        const data = await response.json();
                        issuesToShow = data.issues || [];
                        allIssues = issuesToShow; // Cache for future use
                    } else {
                        throw new Error('Failed to fetch dashboard data');
                    }
                }
                
                console.log('Opening full issues modal with', issuesToShow.length, 'issues');
                openFullIssuesModal(issuesToShow);
                
            } catch (error) {
                console.error('Failed to open full issues view:', error);
                showToast('Failed to load issues view. Please try again.', 'error');
            }
        });

        // Chat input handlers
        document.getElementById('query-btn').addEventListener('click', handleQuery);
        document.getElementById('query-input').addEventListener('keyup', (event) => {
            if (event.key === 'Enter') handleQuery();
        });
        document.getElementById('clear-chat-btn').addEventListener('click', clearChat);

        // Modal filtering handlers
        document.getElementById('modal-severity-filter').addEventListener('change', applyModalFilters);
        document.getElementById('modal-sort-issues').addEventListener('change', applyModalFilters);
        document.getElementById('modal-search-issues').addEventListener('input', applyModalFilters);
        document.getElementById('modal-clear-filters').addEventListener('click', () => {
            document.getElementById('modal-severity-filter').value = '';
            document.getElementById('modal-sort-issues').value = 'timestamp-desc';
            document.getElementById('modal-search-issues').value = '';
            applyModalFilters();
        });

        // Rule modal filtering handlers
        document.getElementById('rule-severity-filter').addEventListener('change', filterRuleIssues);
        document.getElementById('rule-search-issues').addEventListener('input', filterRuleIssues);
        document.getElementById('rule-clear-filters').addEventListener('click', () => {
            document.getElementById('rule-severity-filter').value = '';
            document.getElementById('rule-search-issues').value = '';
            selectedRuleFilter = null;
            filterRuleIssues();
        });

        // Grid/List view handlers
        document.getElementById('grid-view-btn').addEventListener('click', () => {
            isGridView = true;
            document.getElementById('grid-view-btn').classList.add('bg-blue-600');
            document.getElementById('grid-view-btn').classList.remove('bg-gray-600');
            document.getElementById('list-view-btn').classList.add('bg-gray-600');
            document.getElementById('list-view-btn').classList.remove('bg-blue-600');
            applyModalFilters();
        });

        document.getElementById('list-view-btn').addEventListener('click', () => {
            isGridView = false;
            document.getElementById('list-view-btn').classList.add('bg-blue-600');
            document.getElementById('list-view-btn').classList.remove('bg-gray-600');
            document.getElementById('grid-view-btn').classList.add('bg-gray-600');
            document.getElementById('grid-view-btn').classList.remove('bg-blue-600');
            applyModalFilters();
        });

        document.getElementById('issue-query-btn').addEventListener('click', handleIssueQuery);
        document.getElementById('issue-query-input').addEventListener('keyup', (event) => {
            if (event.key === 'Enter') handleIssueQuery();
        });

        // Main action buttons
        document.getElementById('find-more-btn').addEventListener('click', triggerAnalysis);
        document.getElementById('settings-btn').addEventListener('click', () => {
            loadSettings();
            settingsModal.style.display = 'flex';
        });

        // Script actions
        document.getElementById('copy-script-btn').onclick = () => {
            const scriptText = document.getElementById('script-content').textContent;
            navigator.clipboard.writeText(scriptText).then(() => {
                showToast('Script copied to clipboard!');
            });
        };

        document.getElementById('download-script-btn').onclick = () => {
            const scriptText = document.getElementById('script-content').textContent;
            const blob = new Blob([scriptText], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `wazuh_repair_script_${new Date().getTime()}.sh`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Script downloaded successfully!');
        };

        // Settings handling
        document.getElementById('settings-form').addEventListener('submit', (event) => {
            event.preventDefault();
            const formData = Object.fromEntries(new FormData(event.target));
            saveSettings(formData);
        });

        document.getElementById('clear-db-btn').addEventListener('click', () => {
            if (confirm('⚠️ Are you sure you want to clear the entire database? This action cannot be undone and will remove all logs, issues, and analysis data.')) {
                clearDatabase();
            }
        });

        async function loadSettings() {
            try {
                const response = await fetch('/api/settings');
                if (!response.ok) throw new Error('Failed to load settings');
                const settings = await response.json();
                const form = document.getElementById('settings-form');
                for (const [key, value] of Object.entries(settings)) {
                    const input = form.querySelector(`[name="${key}"]`);
                    if (input) input.value = value;
                }
            } catch (error) {
                console.error("Failed to load settings:", error);
                showToast('Failed to load settings', 'error');
            }
        }

        async function saveSettings(formData) {
            try {
                const response = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                if (!response.ok) throw new Error('Failed to save settings');
                settingsModal.style.display = 'none';
                showToast('Settings saved successfully!');
            } catch (error) {
                console.error("Failed to save settings:", error);
                showToast('Failed to save settings', 'error');
            }
        }

        async function clearDatabase() {
            try {
                const response = await fetch('/api/clear_db', { method: 'POST' });
                if (!response.ok) throw new Error('Failed to clear database');
                fetchData();
                settingsModal.style.display = 'none';
                showToast('Database cleared successfully!');
            } catch (error) {
                console.error("Failed to clear database:", error);
                showToast('Failed to clear database', 'error');
            }
        }

        // Initialize everything
        document.addEventListener('DOMContentLoaded', () => {
            console.log('DOM loaded, initializing dashboard...');
            
            try {
                initializeCharts();
                console.log('Charts initialized successfully');
            } catch (error) {
                console.error('Error initializing charts:', error);
            }
            
            try {
                fetchData();
                console.log('Initial data fetch started');
            } catch (error) {
                console.error('Error during initial data fetch:', error);
            }
            
            // Regular refresh every 15 seconds
            setInterval(() => {
                try {
                    fetchData();
                } catch (error) {
                    console.error('Error during periodic data fetch:', error);
                }
            }, 15000);
            
            // More frequent status updates every 3 seconds when app is active
            setInterval(() => {
                try {
                    const currentStatus = document.getElementById('app-status')?.textContent;
                    if (currentStatus && !currentStatus.includes('Idle') && !currentStatus.includes('Ready')) {
                        // Fetch data more frequently during active operations
                        fetchData();
                    }
                } catch (error) {
                    console.error('Error during status check:', error);
                }
            }, 3000);
            
            console.log('Dashboard initialization complete');
        });
    </script>
</body>
</html>
"""

# --- Configuration Defaults ---
DEFAULT_SETTINGS = {
    "processing_interval": 300,
    "initial_scan_count": 200,  # Increased from 100
    "log_batch_size": 100000,
    "search_k": 500,  # Increased from 200 for richer context
    "analysis_k": 500,  # Increased from 200 for richer context
    "max_issues": 1000,
    "max_output_tokens": 8000,
}

# File Paths
LOG_FILE = "/var/ossec/logs/alerts/alerts.json"
DB_DIR = "/var/ossec/integrations/threat_hunter_db"
LOG_POSITION_FILE = os.path.join(DB_DIR, "log_position.txt")
VECTOR_DB_FILE = os.path.join(DB_DIR, "vector_db.faiss")
METADATA_DB_FILE = os.path.join(DB_DIR, "metadata.json")
DASHBOARD_DATA_FILE = os.path.join(DB_DIR, "dashboard_data.json")
SETTINGS_FILE = os.path.join(DB_DIR, "settings.json")
IGNORED_ISSUES_FILE = os.path.join(DB_DIR, "ignored_issues.json")

# AI & Embeddings
LITE_MODEL = "gemini-2.5-flash-lite-preview-06-17"
FULL_MODEL = "gemini-2.5-flash"
PRO_MODEL = "gemini-2.5-pro"
EMBEDDING_MODEL = 'Snowflake/snowflake-arctic-embed-m'

# Model Quotas (RPM, TPM per minute)
MODEL_QUOTA = {
    "pro": (5, 250_000),
    "flash": (10, 250_000),
    "flash-lite": (15, 250_000)
}

# Multiple API Keys Support
GEMINI_API_KEYS = []
api_key_1 = os.getenv("GEMINI_API_KEY")
api_key_2 = os.getenv("GEMINI_API_KEY_2")
api_key_3 = os.getenv("GEMINI_API_KEY_3")

if api_key_1:
    GEMINI_API_KEYS.append(api_key_1)
if api_key_2:
    GEMINI_API_KEYS.append(api_key_2)
if api_key_3:
    GEMINI_API_KEYS.append(api_key_3)

# Security - Get auth credentials from environment
BASIC_AUTH_USER = os.getenv("BASIC_AUTH_USER")
BASIC_AUTH_PASS = os.getenv("BASIC_AUTH_PASS")

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure genai
if GEMINI_API_KEYS:
    genai.configure(api_key=GEMINI_API_KEYS[0])

# --- Token Bucket Implementation (Simplified) ---
class TokenBucket:
    """Simple token bucket for rate limiting"""
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = asyncio.Lock()
    
    async def consume(self, tokens: int) -> bool:
        """Try to consume tokens, returns True if successful"""
        async with self.lock:
            now = time.time()
            # Refill tokens based on time passed
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    async def wait_for_tokens(self, tokens: int):
        """Wait until enough tokens are available"""
        while not await self.consume(tokens):
            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.refill_rate
            await asyncio.sleep(wait_time + 0.1)

# --- Token Counting ---
def count_tokens_local(text: str, model_name: str) -> int:
    """Count tokens using Google's official count_tokens method with robust fallback"""
    try:
        # Use the genai.GenerativeModel count_tokens method
        model = genai.GenerativeModel(model_name)
        result = model.count_tokens(text)
        return result.total_tokens
        
    except Exception as e:
        # Fallback estimation if count_tokens fails
        logging.warning(f"Token counting failed for {model_name}: {e}. Using character-based estimate.")
        
        # More accurate fallback estimation
        # English text: ~4 chars per token
        # JSON/structured text: ~3 chars per token  
        # Code: ~2.5 chars per token
        
        char_count = len(text.encode('utf-8'))
        
        # Determine text type for better estimation
        if text.strip().startswith('{') or '"' in text[:100]:
            # Looks like JSON/structured data
            estimated_tokens = char_count // 3
        else:
            # Regular text
            estimated_tokens = char_count // 4
            
        return max(1, estimated_tokens)

# --- Metrics ---
class MetricsCollector:
    def __init__(self):
        self.gemini_requests_total = defaultdict(int)
        self.gemini_429_total = defaultdict(int)
        self.gemini_tokens_total = defaultdict(lambda: defaultdict(int))
        self.worker_cycle_seconds = 0.0
        self.lock = asyncio.Lock()
    
    async def increment_requests(self, model: str):
        async with self.lock:
            self.gemini_requests_total[model] += 1
    
    async def increment_429s(self, model: str):
        async with self.lock:
            self.gemini_429_total[model] += 1
    
    async def add_tokens(self, model: str, direction: str, tokens: int):
        async with self.lock:
            self.gemini_tokens_total[model][direction] += tokens
    
    async def set_cycle_time(self, seconds: float):
        async with self.lock:
            self.worker_cycle_seconds = seconds
    
    async def get_metrics_text(self) -> str:
        async with self.lock:
            lines = []
            
            # Requests
            for model, count in self.gemini_requests_total.items():
                lines.append(f'gemini_requests_total{{model="{model}"}} {count}')
            
            # 429s
            for model, count in self.gemini_429_total.items():
                lines.append(f'gemini_429_total{{model="{model}"}} {count}')
            
            # Tokens
            for model, directions in self.gemini_tokens_total.items():
                for direction, count in directions.items():
                    lines.append(f'gemini_tokens_total{{model="{model}",direction="{direction}"}} {count}')
            
            # Worker cycle time
            lines.append(f'worker_cycle_seconds {self.worker_cycle_seconds}')
            
            return '\n'.join(lines) + '\n'

# --- Global State & Models ---
app = FastAPI(title="Wazuh Threat Hunter Pro (Gemini Edition)")
security = HTTPBasic()
embedding_model = None
vector_db = None
metadata_db = {}
dashboard_data = {
    "summary": "Initializing...",
    "last_run": None,
    "issues": [],
    "stats": {"total_logs": 0, "new_logs": 0, "anomalies": 0},
    "log_trend": [],
    "rule_distribution": {},
    "active_api_key_index": 0,
    "status": "Initializing..."
}
settings = DEFAULT_SETTINGS.copy()
ignored_issue_ids = set()

# Application status tracking
app_status = "Initializing..."

def set_app_status(status: str):
    global app_status
    app_status = status
    dashboard_data["status"] = status
    logging.info(f"Status: {status}")

# Thread-safe locks
vector_lock = asyncio.Lock()
api_key_lock = asyncio.Lock()

# Rate limiting: Simple buckets per API key
# rpm_buckets[api_key] = TokenBucket, tpm_buckets[api_key] = TokenBucket
rpm_buckets = {}
tpm_buckets = {}

current_api_key_index = 0
consecutive_failures = defaultdict(int)  # Track failures per key

# HTTP client
http_client: Optional[httpx.AsyncClient] = None

# Metrics
metrics = MetricsCollector()

# --- Pydantic Models ---
class Issue(BaseModel):
    id: str
    timestamp: str
    severity: str
    title: str
    summary: str
    recommendation: str
    related_logs: List[str]

class DashboardData(BaseModel):
    summary: str
    last_run: Optional[str]
    issues: List[Issue]
    stats: dict
    log_trend: list
    rule_distribution: dict
    active_api_key_index: Optional[int] = 0
    status: Optional[str] = "Initializing..."

class QueryRequest(BaseModel):
    query: str
    history: Optional[List[dict]] = Field(default_factory=list)

class Settings(BaseModel):
    processing_interval: Optional[int]
    initial_scan_count: Optional[int]
    log_batch_size: Optional[int]
    search_k: Optional[int]
    analysis_k: Optional[int]
    max_issues: Optional[int]
    max_output_tokens: Optional[int]

# --- Persistence Functions ---
async def load_dashboard_data():
    global dashboard_data
    if os.path.exists(DASHBOARD_DATA_FILE):
        try:
            async with aiofiles.open(DASHBOARD_DATA_FILE, 'r') as f:
                loaded = json.loads(await f.read())
                dashboard_data.update(loaded)
            logging.info("Loaded dashboard data from file.")
        except Exception as e:
            logging.error(f"Failed to load dashboard data: {e}")

async def save_dashboard_data():
    try:
        async with vector_lock:
            async with aiofiles.open(DASHBOARD_DATA_FILE, 'w') as f:
                await f.write(json.dumps(dashboard_data))
        logging.info("Saved dashboard data to file.")
    except Exception as e:
        logging.error(f"Failed to save dashboard data: {e}")

def load_settings():
    global settings
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                loaded = json.load(f)
                settings.update({k: v for k, v in loaded.items() if k in DEFAULT_SETTINGS})
            logging.info("Loaded settings from file.")
        except Exception as e:
            logging.error(f"Failed to load settings: {e}")

def save_settings():
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f)
        logging.info("Saved settings to file.")
    except Exception as e:
        logging.error(f"Failed to save settings: {e}")

def load_ignored_issues():
    global ignored_issue_ids
    if os.path.exists(IGNORED_ISSUES_FILE):
        try:
            with open(IGNORED_ISSUES_FILE, 'r') as f:
                ignored_issue_ids = set(json.load(f))
            logging.info(f"Loaded {len(ignored_issue_ids)} ignored issues from file.")
        except Exception as e:
            logging.error(f"Failed to load ignored issues: {e}")

def save_ignored_issues():
    try:
        with open(IGNORED_ISSUES_FILE, 'w') as f:
            json.dump(list(ignored_issue_ids), f)
        logging.info(f"Saved {len(ignored_issue_ids)} ignored issues to file.")
    except Exception as e:
        logging.error(f"Failed to save ignored issues: {e}")

# --- Vector Database & Metadata ---
def initialize_vector_db():
    global vector_db, metadata_db, embedding_model
    print(f"Creating database directory: {DB_DIR}")
    os.makedirs(DB_DIR, exist_ok=True)
    
    logging.info("Loading embedding model...")
    print("Loading embedding model...")
    
    try:
        embedding_model = SentenceTransformer(EMBEDDING_MODEL)
        embedding_dim = embedding_model.get_sentence_embedding_dimension()
        print(f"Embedding model loaded. Dimension: {embedding_dim}")
    except Exception as e:
        print(f"FAILED to load embedding model: {e}")
        logging.error(f"FAILED to load embedding model: {e}")
        raise

    if os.path.exists(VECTOR_DB_FILE):
        logging.info("Loading existing vector database...")
        print("Loading existing vector database...")
        try:
            vector_db = faiss.read_index(VECTOR_DB_FILE)
            with open(METADATA_DB_FILE, 'r') as f:
                metadata_db = json.load(f)
            logging.info(f"Loaded {len(metadata_db)} metadata entries and {vector_db.ntotal} vectors")
            print(f"Loaded {len(metadata_db)} metadata entries and {vector_db.ntotal} vectors")
        except Exception as e:
            logging.error(f"Failed to load vector database: {e}, creating new one")
            print(f"Failed to load existing DB, creating new one: {e}")
            vector_db = faiss.IndexFlatL2(embedding_dim)
            vector_db = faiss.IndexIDMap(vector_db)
    else:
        logging.info("Creating new vector database.")
        print("Creating new vector database.")
        vector_db = faiss.IndexFlatL2(embedding_dim)
        vector_db = faiss.IndexIDMap(vector_db)
        save_vector_db()
    
    print("Vector database initialization complete.")

def save_vector_db():
    if vector_db:
        try:
            faiss.write_index(vector_db, VECTOR_DB_FILE)
            with open(METADATA_DB_FILE, 'w') as f:
                json.dump(metadata_db, f)
            logging.info("Vector database saved.")
        except Exception as e:
            logging.error(f"Failed to save vector database: {e}")

async def add_to_vector_db(log_entries):
    if not log_entries: 
        return
    
    set_app_status("Checking for duplicates...")
    # Compute SHA256 hashes for deduplication
    unique_logs = {}
    async with vector_lock:
        for log in log_entries:
            sha = hashlib.sha256(json.dumps(log, sort_keys=True).encode()).hexdigest()
            if sha not in metadata_db:  # Skip if already exists
                unique_logs[sha] = log
    
    if not unique_logs:
        logging.info("No new unique logs to add after deduplication")
        set_app_status("Ready")
        return
    
    set_app_status(f"Generating embeddings for {len(unique_logs)} logs...")
    texts_for_embedding = []
    faiss_ids = []
    
    for sha, log in unique_logs.items():
        # Generate random FAISS ID
        faiss_id = np.random.randint(0, 2**63 - 1, dtype=np.int64)
        faiss_ids.append(faiss_id)
        
        # Store metadata with SHA as key and FAISS ID
        log['sha256'] = sha
        log['faiss_id'] = int(faiss_id)
        
        # Create embedding text
        embedding_text = json.dumps({
            "timestamp": log.get("timestamp"),
            "rule": log.get("rule", {}),
            "agent": log.get("agent", {}),
            "location": log.get("location"),
            "data": log.get("data", {}),
            "full_log": log.get("full_log")
        })
        texts_for_embedding.append(embedding_text)
    
    # Generate embeddings in chunks
    embeddings_list = []
    chunk_size = 64  # Smaller chunks for stability
    
    for i in range(0, len(texts_for_embedding), chunk_size):
        chunk = texts_for_embedding[i:i+chunk_size]
        set_app_status(f"Vectorizing chunk {i//chunk_size + 1}/{(len(texts_for_embedding)//chunk_size) + 1}...")
        try:
            chunk_embeddings = await asyncio.to_thread(
                embedding_model.encode, chunk, convert_to_numpy=True, batch_size=32
            )
            embeddings_list.append(chunk_embeddings)
        except Exception as e:
            logging.error(f"Failed to generate embeddings for chunk {i}: {e}")
            continue
    
    if not embeddings_list:
        logging.error("Failed to generate any embeddings")
        set_app_status("Embedding generation failed")
        return
    
    embeddings = np.vstack(embeddings_list)
    
    set_app_status("Adding to vector database...")
    # Thread-safe FAISS operations
    async with vector_lock:
        try:
            vector_db.add_with_ids(embeddings, np.array(faiss_ids))
            # Update metadata
            for sha, log in unique_logs.items():
                metadata_db[sha] = log
        except Exception as e:
            logging.error(f"Failed to add to FAISS: {e}")
            set_app_status("Vector DB update failed")
            return
    
    logging.info(f"Added {len(unique_logs)} new unique items to vector DB.")
    set_app_status("Ready")

async def search_vector_db(query_text: str, k: int = 10):
    if not query_text or not vector_db or vector_db.ntotal == 0: 
        return []
    
    try:
        query_embedding = await asyncio.to_thread(
            embedding_model.encode, [query_text], convert_to_numpy=True
        )
        
        async with vector_lock:
            distances, indices = vector_db.search(query_embedding, k)
        
        results = []
        async with vector_lock:
            for i, faiss_id in enumerate(indices[0]):
                if faiss_id != -1:
                    # Find metadata by FAISS ID
                    for sha, metadata in metadata_db.items():
                        if metadata.get('faiss_id') == faiss_id:
                            results.append({
                                "id": sha,
                                "metadata": metadata,
                                "distance": float(distances[0][i])
                            })
                            break
        return results
    except Exception as e:
        logging.error(f"Error in vector search: {e}")
        return []

async def clear_database():
    global vector_db, metadata_db
    async with vector_lock:
        vector_db = faiss.IndexFlatL2(embedding_model.get_sentence_embedding_dimension())
        vector_db = faiss.IndexIDMap(vector_db)
        metadata_db = {}
        dashboard_data["stats"]["total_logs"] = 0
        dashboard_data["issues"] = []
        dashboard_data["stats"]["anomalies"] = 0
        dashboard_data["log_trend"] = []
        dashboard_data["rule_distribution"] = {}
        save_vector_db()
        await save_dashboard_data()
        if os.path.exists(LOG_POSITION_FILE):
            os.remove(LOG_POSITION_FILE)
    logging.info("Database cleared.")

# --- Log Processing ---
def get_log_position():
    if not os.path.exists(LOG_POSITION_FILE): 
        print(f"No log position file found at {LOG_POSITION_FILE}, starting from 0")
        return 0
    try:
        with open(LOG_POSITION_FILE, 'r') as f:
            pos = int(f.read().strip())
            print(f"Read log position: {pos}")
            return pos
    except (ValueError, FileNotFoundError) as e:
        print(f"Error reading log position file: {e}, defaulting to 0")
        return 0

def set_log_position(position):
    try:
        with open(LOG_POSITION_FILE, 'w') as f: 
            f.write(str(position))
        print(f"Set log position to: {position}")
    except Exception as e:
        logging.error(f"Failed to set log position: {e}")
        print(f"ERROR setting log position: {e}")

async def process_logs():
    print(f"Processing logs from: {LOG_FILE}")
    logging.info(f"Processing logs from: {LOG_FILE}")
    
    # Check if directory exists
    log_dir = os.path.dirname(LOG_FILE)
    print(f"Log directory: {log_dir}")
    print(f"Log directory exists: {os.path.exists(log_dir)}")
    
    if os.path.exists(log_dir):
        try:
            files_in_dir = os.listdir(log_dir)
            print(f"Files in log directory: {files_in_dir}")
        except Exception as e:
            print(f"Error listing log directory: {e}")
    
    if not os.path.exists(LOG_FILE):
        logging.warning(f"Log file not found at {LOG_FILE}. Skipping processing.")
        print(f"WARNING: Log file not found at {LOG_FILE}")
        
        # Check for alternative locations or names
        alternative_paths = [
            "/var/ossec/logs/alerts.json",
            "/var/ossec/logs/alerts/alerts.log",
            "/opt/ossec/logs/alerts/alerts.json",
        ]
        
        for alt_path in alternative_paths:
            if os.path.exists(alt_path):
                print(f"Found alternative log file at: {alt_path}")
                break
        else:
            print("No alternative log files found")
        
        return []

    print(f"Log file exists. Current size: {os.path.getsize(LOG_FILE)} bytes")

    logs_to_process = []
    current_position = 0
    is_initial_run = vector_db.ntotal == 0

    print(f"Vector DB has {vector_db.ntotal if vector_db else 0} entries")
    print(f"Is initial run: {is_initial_run}")

    last_position = get_log_position()
    try:
        file_size = os.path.getsize(LOG_FILE)
    except OSError as e:
        logging.error(f"Failed to get file size: {e}")
        print(f"ERROR: Failed to get file size: {e}")
        return []
    
    print(f"Last position: {last_position}, File size: {file_size}")
    
    # Handle log rotation
    if last_position > file_size:
        logging.info("Log file appears to have been rotated. Resetting position to 0.")
        print("Log file rotated. Resetting position to 0.")
        last_position = 0

    if is_initial_run:
        logging.info(f"First run detected. Performing initial scan of the last {settings['initial_scan_count']} logs from {LOG_FILE}.")
        print(f"First run detected. Scanning last {settings['initial_scan_count']} logs.")
        try:
            # Read initial logs
            with open(LOG_FILE, 'r', errors='ignore') as f:
                if file_size > 1024 * 1024:  # 1MB
                    # For large files, seek to end and read backwards
                    f.seek(max(0, file_size - 1024 * 1024))
                    lines = f.readlines()
                    log_lines = lines[-settings['initial_scan_count']:]
                else:
                    log_lines = list(f)[-settings['initial_scan_count']:]
                current_position = file_size
            
            print(f"Read {len(log_lines)} lines from log file")
            
            for line_num, line in enumerate(log_lines):
                try:
                    logs_to_process.append(json.loads(line.strip()))
                except json.JSONDecodeError as e:
                    if line_num < 5:  # Only log first few decode errors
                        print(f"JSON decode error on line {line_num}: {e}")
                    continue
            logging.info(f"Initial scan collected {len(logs_to_process)} recent logs for processing.")
            print(f"Initial scan collected {len(logs_to_process)} logs")
        except Exception as e:
            logging.error(f"Error during initial scan: {e}")
            print(f"ERROR during initial scan: {e}")
            return []
    else:
        logging.info(f"Checking for new logs since last file position: {last_position}")
        print(f"Checking for new logs since position {last_position}")
        try:
            with open(LOG_FILE, 'r', errors='ignore') as f:
                f.seek(last_position)
                log_count = 0
                while log_count < settings['log_batch_size']:
                    line = f.readline()
                    if not line: 
                        break
                    try:
                        logs_to_process.append(json.loads(line.strip()))
                        log_count += 1
                    except json.JSONDecodeError:
                        continue
                current_position = f.tell()
            print(f"Found {len(logs_to_process)} new logs since last position")
        except Exception as e:
            logging.error(f"Error reading logs: {e}")
            print(f"ERROR reading logs: {e}")
            return []

    set_log_position(current_position)
    print(f"Set new log position to: {current_position}")

    if logs_to_process:
        logging.info(f"Processing {len(logs_to_process)} logs for deduplication and vector storage.")
        print(f"Processing {len(logs_to_process)} logs for vector storage...")
        await add_to_vector_db(logs_to_process)
        save_vector_db()
        print("Vector DB updated and saved")
    else:
        logging.info("No new logs found in this cycle.")
        print("No new logs found in this cycle.")

    dashboard_data["stats"]["new_logs"] = len(logs_to_process)
    dashboard_data["stats"]["total_logs"] = vector_db.ntotal if vector_db else 0
    await save_dashboard_data()
    print(f"Dashboard updated: {len(logs_to_process)} new logs, {dashboard_data['stats']['total_logs']} total")
    return logs_to_process

# --- AI Analysis (Gemini) ---
def get_model_family(model_name: str) -> str:
    """Extract model family from full model name"""
    if "pro" in model_name.lower():
        return "pro"
    elif "lite" in model_name.lower():
        return "flash-lite"
    else:
        return "flash"

def get_or_create_bucket(api_key: str, bucket_type: str) -> TokenBucket:
    """Get or create rate limiting bucket for API key + bucket type"""
    buckets_dict = rpm_buckets if bucket_type == "rpm" else tpm_buckets
    
    if api_key not in buckets_dict:
        if bucket_type == "rpm":
            # Use actual Gemini API limits
            buckets_dict[api_key] = TokenBucket(10, 10.0 / 60.0)  # Conservative for Flash (10 RPM)
        else:  # tpm
            # CORRECT TPM LIMITS - 250,000 per minute for most models
            buckets_dict[api_key] = TokenBucket(250_000, 250_000.0 / 60.0)  # Actual Gemini limit
    
    return buckets_dict[api_key]

async def rotate_api_key() -> Tuple[str, int]:
    """Rotate to the next API key"""
    global current_api_key_index
    if not GEMINI_API_KEYS:
        raise HTTPException(status_code=500, detail="No GEMINI_API_KEY configured.")
    
    async with api_key_lock:
        old_index = current_api_key_index
        current_api_key_index = (current_api_key_index + 1) % len(GEMINI_API_KEYS)
        dashboard_data["active_api_key_index"] = current_api_key_index
        new_key = GEMINI_API_KEYS[current_api_key_index]
        # Configure genai with new key
        genai.configure(api_key=new_key)
        # Reset failure count for old key
        consecutive_failures[GEMINI_API_KEYS[old_index]] = 0
        logging.info(f"Rotated from API key {old_index + 1} to {current_api_key_index + 1}")
    
    return new_key, current_api_key_index

async def call_gemini_api(prompt: str, is_json_output: bool = False, model_name: str = FULL_MODEL):
    global http_client, current_api_key_index
    
    if not GEMINI_API_KEYS:
        raise HTTPException(status_code=500, detail="No GEMINI_API_KEY configured.")
    
    if not http_client:
        http_client = httpx.AsyncClient(timeout=180.0)

    model_family = get_model_family(model_name)
    model_display = {'pro': 'Gemini 2.5 Pro', 'flash': 'Gemini 2.5 Flash', 'flash-lite': 'Gemini 2.5 Flash Lite'}[model_family]
    
    # Count tokens locally
    input_tokens = count_tokens_local(prompt, model_name)
    expected_output = min(settings["max_output_tokens"], 8192)
    total_expected = input_tokens + expected_output
    
    logging.info(f"About to call {model_display} with {input_tokens} input tokens, {expected_output} expected output")
    
    # Prompt size guard - CORRECTED to actual Gemini limits
    if total_expected > 200_000:  # Conservative limit within 250K TPM capacity
        raise HTTPException(status_code=400, detail=f"Prompt too large: {total_expected} tokens exceeds 200K safe limit")
    
    logging.info(f"Token usage: {input_tokens:,} input + {expected_output:,} expected output = {total_expected:,} total")
    logging.info(f"TPM Utilization: {total_expected/250_000*100:.1f}% of 250K TPM limit")
    
    max_retries = 15
    retry_count = 0
    
    while retry_count < max_retries:
        current_key = GEMINI_API_KEYS[current_api_key_index]
        
        # Get rate limiting buckets
        rpm_bucket = get_or_create_bucket(current_key, "rpm")
        tpm_bucket = get_or_create_bucket(current_key, "tpm")
        
        # Wait for rate limits
        logging.info(f"Waiting for rate limits (key {current_api_key_index + 1})...")
        await rpm_bucket.wait_for_tokens(1)  # 1 request
        await tpm_bucket.wait_for_tokens(total_expected)  # tokens
        
        logging.info(f"Sending request to {model_display} API using key {current_api_key_index + 1} (attempt {retry_count + 1})...")
        
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={current_key}"
        
        payload = {
            "contents": [{"parts":[{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": expected_output}
        }

        if is_json_output:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        try:
            response = await http_client.post(
                api_url,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            await metrics.increment_requests(model_family)
            
            if response.status_code == 429:
                await metrics.increment_429s(model_family)
                
                # Track consecutive failures
                consecutive_failures[current_key] += 1
                
                # Check for Retry-After header
                retry_after = response.headers.get('Retry-After')
                wait_time = int(retry_after) if retry_after else 2
                
                logging.warning(f"Rate limit hit on key {current_api_key_index + 1}, waiting {wait_time}s (failure #{consecutive_failures[current_key]})")
                await asyncio.sleep(wait_time)
                
                # After 3 consecutive 429s, rotate key
                if consecutive_failures[current_key] >= 3:
                    logging.warning("3 consecutive 429s, rotating API key")
                    new_key, new_index = await rotate_api_key()
                    continue
                
                retry_count += 1
                continue
            
            response.raise_for_status()
            
            # Reset failure count on success
            consecutive_failures[current_key] = 0
            
            result = response.json()
            await metrics.add_tokens(model_family, "in", input_tokens)
            await metrics.add_tokens(model_family, "out", expected_output)
            
            logging.info(f"Successful response from {model_display}")
            
            if 'candidates' in result and result['candidates']:
                candidate = result['candidates'][0]
                if 'content' in candidate and 'parts' in candidate['content'] and candidate['content']['parts']:
                    part = candidate['content']['parts'][0]
                    if 'text' in part:
                        return part['text']
                    else:
                        raise ValueError("No 'text' in part")
                else:
                    finish_reason = candidate.get('finishReason', 'UNKNOWN')
                    logging.warning(f"Generation stopped with reason: {finish_reason}")
                    return f"Generation stopped: {finish_reason}"
            elif 'error' in result:
                error_msg = result['error'].get('message', 'Unknown error')
                logging.error(f"Gemini API Error: {error_msg}")
                raise HTTPException(status_code=503, detail=f"Gemini API Error: {error_msg}")
            else:
                raise HTTPException(status_code=500, detail="Invalid response structure from Gemini API.")

        except httpx.TimeoutException as e:
            logging.warning(f"Request timed out: {e}. Retrying...")
            await asyncio.sleep(min(2 ** retry_count, 30))
            retry_count += 1
            continue
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                continue  # Already handled above
            logging.error(f"HTTP error: {e}")
            raise HTTPException(status_code=503, detail=f"Gemini API request failed: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during Gemini API call: {e}")
            raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")
    
    raise HTTPException(status_code=429, detail="Max retries exceeded.")

def prepare_full_log_context(logs: list) -> str:
    """Prepares a JSON string of full logs - now handles much larger volumes."""
    context_list = [log.get('metadata', log) for log in logs if log.get('metadata', log)]
    # Increased from 50 to 300 logs for much richer context
    return json.dumps(context_list[:300], indent=2)

def extract_json_from_string(text: str) -> Optional[str]:
    """Finds and extracts valid JSON object from AI response with robust parsing."""
    if not text:
        return None
    
    text = text.strip()
    
    # Remove markdown code blocks if present
    if "```json" in text:
        text = text.split("```json", 1)[-1].rsplit("```", 1)[0].strip()
    elif "```" in text:
        # Check if it looks like a code block
        if text.count("```") >= 2:
            text = text.split("```", 1)[-1].rsplit("```", 1)[0].strip()
    
    # Simple approach first - look for complete JSON objects
    start_pos = text.find('{')
    if start_pos == -1:
        return None
    
    # Find the matching closing brace
    brace_count = 0
    end_pos = -1
    
    for i in range(start_pos, len(text)):
        if text[i] == '{':
            brace_count += 1
        elif text[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                end_pos = i + 1
                break
    
    if end_pos == -1:
        # No matching closing brace found, try taking everything from first { to last }
        end_pos = text.rfind('}') + 1
        if end_pos == 0:
            return None
    
    json_str = text[start_pos:end_pos]
    
    # Try to parse as-is first
    try:
        json.loads(json_str)
        return json_str
    except json.JSONDecodeError:
        pass
    
    # Clean up common JSON issues
    cleaned = json_str
    
    # Fix trailing commas
    cleaned = re.sub(r',(\s*[}\]])', r'\1', cleaned)
    
    # Fix unescaped quotes in strings (simple approach)
    # This is tricky to do perfectly, so we'll be conservative
    
    # Try the cleaned version
    try:
        json.loads(cleaned)
        return cleaned
    except json.JSONDecodeError:
        pass
    
    # If still failing, try to reconstruct a basic structure
    # Look for key patterns in the text
    overall_summary_match = re.search(r'"overall_summary"\s*:\s*"([^"]*(?:\\.[^"]*)*)"', text, re.DOTALL)
    issues_match = re.search(r'"identified_issues"\s*:\s*\[(.*)\]', text, re.DOTALL)
    
    if overall_summary_match:
        summary = overall_summary_match.group(1)
        # Basic reconstruction
        reconstructed = {
            "overall_summary": summary,
            "identified_issues": []
        }
        
        # Try to extract issues if found
        if issues_match:
            try:
                # This is a simplified extraction - in production you'd want more robust parsing
                issues_text = issues_match.group(1)
                if issues_text.strip():
                    # Try to parse individual issues
                    # For now, just return empty issues array to avoid parsing errors
                    pass
            except:
                pass
        
        try:
            reconstructed_json = json.dumps(reconstructed)
            json.loads(reconstructed_json)  # Validate
            return reconstructed_json
        except:
            pass
    
    logging.error(f"Could not extract valid JSON. Text length: {len(text)}")
    logging.error(f"Text preview: {text[:500]}...")
    if len(text) > 500:
        logging.error(f"Text ending: ...{text[-200:]}")
    
    return None

def generate_issue_signature(issue_data: dict) -> str:
    """Generate a consistent signature for issue deduplication"""
    # Create signature based on key characteristics
    severity = issue_data.get('severity', '').lower()
    title_words = issue_data.get('title', '').lower().split()[:5]  # First 5 words
    summary_words = issue_data.get('summary', '').lower().split()[:10]  # First 10 words
    
    # Create a normalized signature
    signature_text = f"{severity}|{' '.join(title_words)}|{' '.join(summary_words)}"
    return hashlib.sha256(signature_text.encode()).hexdigest()[:16]

async def generate_retrieval_queries(recent_logs_summary: str) -> List[str]:
    logging.info("Generating retrieval queries...")
    set_app_status("Generating search queries...")
    prompt = f"""Analyze the following summary of recent logs and generate 2 search queries to retrieve relevant historical context from a vector database of past logs. The queries should capture potential patterns, anomalies, or related events.

Recent Logs Summary:
{recent_logs_summary}

Output ONLY a JSON array of strings, e.g., ["query1", "query2"].
"""
    try:
        raw_response = await call_gemini_api(prompt, is_json_output=True, model_name=LITE_MODEL)
        queries = json.loads(raw_response)
        return queries if isinstance(queries, list) else []
    except Exception as e:
        logging.error(f"Failed to generate retrieval queries: {e}")
        return []

async def summarize_logs(logs: list, log_type: str = "historical") -> str:
    if not logs:
        return f"No {log_type} logs available."
    
    # Process larger chunks for efficiency but ensure quality
    chunk_size = 100  # Increased from 25 for better efficiency
    logs_to_process = logs[:500]  # Increased from 50 to process much more
    
    logging.info(f"Summarizing {len(logs_to_process)} {log_type} logs")
    set_app_status(f"Summarizing {len(logs_to_process)} {log_type} logs...")
    
    # For smaller sets, process all at once
    if len(logs_to_process) <= chunk_size:
        logs_str = prepare_full_log_context(logs_to_process)
        
        prompt = f"""Summarize the following {log_type} logs comprehensively. Highlight key patterns, security events, anomalies, correlations, timestamps, source/destination IPs, users, systems, and rule descriptions. Provide detailed context for threat analysis.

{log_type.capitalize()} Logs:
{logs_str}

Output ONLY the comprehensive summary text."""
        
        try:
            set_app_status(f"Sending {log_type} logs to Gemini...")
            summary = await call_gemini_api(prompt, model_name=LITE_MODEL)
            return summary
        except Exception as e:
            logging.error(f"Failed to summarize {log_type} logs: {e}")
            return f"Failed to summarize {log_type} logs: {str(e)}"
    
    # For larger sets, chunk and combine
    summaries = []
    num_chunks = (len(logs_to_process) // chunk_size) + 1
    logging.info(f"Processing {len(logs_to_process)} {log_type} logs in {num_chunks} chunks")
    
    for i in range(0, len(logs_to_process), chunk_size):
        chunk_num = (i // chunk_size) + 1
        set_app_status(f"Summarizing {log_type} chunk {chunk_num}/{num_chunks}...")
        logging.info(f"Processing chunk {chunk_num}/{num_chunks} for {log_type} summary")
        chunk = logs_to_process[i:i+chunk_size]
        logs_str = prepare_full_log_context(chunk)
        
        prompt = f"""Summarize the following {log_type} logs, highlighting key patterns, security events, anomalies, and correlations. Include relevant details like timestamps, IPs, users, systems, and rule descriptions.

{log_type.capitalize()} Logs:
{logs_str}

Output ONLY the summary text."""
        
        try:
            summary = await call_gemini_api(prompt, model_name=LITE_MODEL)
            summaries.append(summary)
        except Exception as e:
            logging.error(f"Failed to summarize chunk {i//chunk_size + 1}: {e}")
            continue

    # Combine summaries
    if len(summaries) > 1:
        logging.info("Combining chunk summaries...")
        set_app_status(f"Combining {len(summaries)} {log_type} summaries...")
        combined_prompt = f"""Combine these {log_type} chunk summaries into a single comprehensive summary. Highlight overall patterns, security trends, anomalies, and key correlations across all timeframes and systems.

Chunk Summaries:
{chr(10).join(summaries)}

Output ONLY the combined comprehensive summary text."""
        
        try:
            combined_summary = await call_gemini_api(combined_prompt, model_name=LITE_MODEL)
            return combined_summary
        except Exception as e:
            logging.error(f"Failed to combine summaries: {e}")
            return chr(10).join(summaries)  # Return individual summaries if combination fails
    else:
        return summaries[0] if summaries else f"No {log_type} logs could be processed"

async def analyze_context_and_identify_issues(recent_logs):
    if not recent_logs:
        dashboard_data["summary"] = "No new activity detected."
        await save_dashboard_data()
        return

    try:
        logging.info(f"Starting AI analysis with {len(recent_logs)} new logs")
        set_app_status("Summarizing recent logs...")
        
        # Prepare context for analysis - USE MUCH MORE CONTEXT
        recent_logs_subset = recent_logs[:200]  # Increased from 50
        recent_summary = await summarize_logs(recent_logs_subset, "recent")

        # Generate retrieval queries
        set_app_status("Generating search queries...")
        retrieval_queries = await generate_retrieval_queries(recent_summary)
        
        # Collect much more historical context
        set_app_status("Searching historical logs...")
        combined_historical_logs = []
        seen_shas = set(log.get('sha256', '') for log in recent_logs)
        
        for query in retrieval_queries[:3]:  # Increased from 2
            try:
                related = await search_vector_db(query, k=100)  # Increased from 25
                for item in related:
                    if item['metadata'].get('sha256') not in seen_shas:
                        combined_historical_logs.append(item['metadata'])
                        seen_shas.add(item['metadata'].get('sha256', ''))
                        if len(combined_historical_logs) >= 300:  # Increased from 50
                            break
                if len(combined_historical_logs) >= 300:
                    break
            except Exception as e:
                logging.error(f"Error in retrieval query '{query}': {e}")

        logging.info(f"Retrieved {len(combined_historical_logs)} historical logs")
        set_app_status("Summarizing historical context...")
        historical_summary = await summarize_logs(combined_historical_logs, "historical")

        # Prepare much larger context for analysis
        recent_logs_str = prepare_full_log_context(recent_logs_subset)  # Now 200 logs instead of 50
        
        # ENHANCED: Include existing issues for deduplication and context
        existing_issues_context = []
        for issue in dashboard_data["issues"][:20]:
            issue_summary = {
                "id": issue["id"],
                "severity": issue["severity"],
                "title": issue["title"],
                "summary": issue["summary"][:200],  # Truncate for space
                "timestamp": issue["timestamp"]
            }
            existing_issues_context.append(issue_summary)
        
        existing_issues_str = json.dumps(existing_issues_context, indent=1)

        prompt = f"""You are a senior security analyst named 'Threat Hunter Pro'. Analyze security logs and return findings in JSON format.

CRITICAL INSTRUCTIONS:
1. Your response must be EXACTLY this JSON structure with NO additional text, explanations, or formatting
2. DO NOT create duplicate issues - check against existing issues first
3. Focus on NEW, UNIQUE security threats not already identified
4. ENSURE related_logs contains actual SHA256 hashes from the provided log data

{{
  "overall_summary": "Brief summary of current security situation and new findings",
  "identified_issues": [
    {{
      "severity": "Low|Medium|High|Critical",
      "title": "Unique, descriptive title not matching existing issues",
      "summary": "Detailed explanation of this specific new threat",
      "recommendation": "Specific action steps for this issue",
      "related_logs": ["sha256_hash1", "sha256_hash2"]
    }}
  ]
}}

**EXISTING ISSUES TO AVOID DUPLICATING:**
{existing_issues_str}

**CONTEXT FOR ANALYSIS:**
Historical Context: {historical_summary[:2000]}

Recent Activity Summary: {recent_summary[:3000]}

Sample Recent Logs: {recent_logs_str[:10000]}

**ANALYSIS REQUIREMENTS:**
1. Create overall_summary describing the CURRENT security situation and any NEW developments
2. Only add to identified_issues array if you find NEW, UNIQUE security incidents not covered by existing issues
3. Use severity: Low, Medium, High, or Critical based on actual threat level
4. Include specific SHA256 hashes in related_logs from the log data provided above
5. If no NEW issues found (only existing ones), use empty identified_issues array: []
6. Focus on ACTIONABLE threats that require immediate attention
7. Avoid creating duplicate or similar issues to those already identified
8. Ensure related_logs contains valid SHA256 hashes from the actual log data

Return ONLY the JSON object above with your analysis data filled in."""
        
        # Token count check
        token_count = count_tokens_local(prompt, FULL_MODEL)
        logging.info(f"Analysis prompt token count: {token_count}")
        
        if token_count > 150_000:
            logging.warning(f"Prompt too large ({token_count} tokens), reducing content")
            # Remove some context to fit within limits
            prompt = prompt.replace(f"Sample Recent Logs: {recent_logs_str[:10000]}", 
                                  "Sample Recent Logs: Content reduced due to size constraints.")
        
        try:
            logging.info("Starting main analysis call...")
            set_app_status("Sending to Gemini AI...")
            raw_response = await call_gemini_api(prompt, is_json_output=True, model_name=FULL_MODEL)
            
            logging.info(f"Raw AI response length: {len(raw_response)} characters")
            logging.debug(f"Raw AI response first 1000 chars: {raw_response[:1000]}")
            logging.debug(f"Raw AI response last 500 chars: {raw_response[-500:]}")
            
            # Log the full response to a file for debugging if needed
            try:
                debug_file = os.path.join(DB_DIR, "last_ai_response.txt")
                with open(debug_file, 'w') as f:
                    f.write(raw_response)
                logging.info(f"Full AI response saved to {debug_file}")
            except Exception as e:
                logging.warning(f"Could not save debug response: {e}")
            
            set_app_status("Parsing AI response...")
            json_str = extract_json_from_string(raw_response)
            if not json_str:
                logging.error("No valid JSON object found in AI response")
                logging.error(f"Response preview: {raw_response[:2000]}...")
                
                # Try a simpler fallback
                fallback_result = {
                    "overall_summary": "AI analysis completed but JSON parsing failed. Raw response saved for debugging.",
                    "identified_issues": []
                }
                analysis_result = fallback_result
                logging.info("Using fallback analysis result")
            else:
                analysis_result = json.loads(json_str)
                logging.info("Successfully parsed AI analysis result")
                
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error: {e}")
            if 'raw_response' in locals():
                logging.error(f"Response around error position: {raw_response[max(0, e.pos-100):e.pos+100]}")
            dashboard_data["summary"] = f"JSON parsing error: {e}"
            await save_dashboard_data()
            return
        except HTTPException as e:
            logging.error(f"HTTP error during AI analysis: {e}")
            dashboard_data["summary"] = f"AI service error: {e.detail}"
            await save_dashboard_data()
            return
        except Exception as e:
            logging.error(f"Unexpected error during AI analysis: {e}")
            dashboard_data["summary"] = f"Unexpected analysis error: {e}"
            await save_dashboard_data()
            return

        # Validate analysis result structure
        if not isinstance(analysis_result, dict):
            logging.error("Analysis result is not a dictionary")
            dashboard_data["summary"] = "Analysis result format error: expected dictionary"
            await save_dashboard_data()
            return
        
        if "overall_summary" not in analysis_result:
            logging.error("Analysis result missing 'overall_summary' field")
            dashboard_data["summary"] = "Analysis completed but missing summary field"
            await save_dashboard_data()
            return

        # Process analysis results
        set_app_status("Processing results...")
        dashboard_data["summary"] = analysis_result.get("overall_summary", "Analysis complete.")
        new_issues = []
        
        identified_issues = analysis_result.get("identified_issues", [])
        if not isinstance(identified_issues, list):
            logging.warning("identified_issues is not a list, treating as empty")
            identified_issues = []
        
        # Enhanced deduplication with signatures
        existing_signatures = set()
        for existing_issue in dashboard_data["issues"]:
            sig = generate_issue_signature(existing_issue)
            existing_signatures.add(sig)
        
        for issue_data in identified_issues:
            try:
                # Validate issue structure
                required_fields = ["severity", "title", "summary", "recommendation"]
                if not all(field in issue_data for field in required_fields):
                    logging.warning(f"Issue missing required fields: {issue_data}")
                    continue
                
                # Check for duplicate using signature
                issue_signature = generate_issue_signature(issue_data)
                if issue_signature in existing_signatures:
                    logging.info(f"Skipping duplicate issue with signature: {issue_signature}")
                    continue
                
                # Generate unique ID and check ignore list
                issue_id = hashlib.sha256(issue_data['title'].encode()).hexdigest()[:10]
                if issue_id in ignored_issue_ids:
                    logging.info(f"Skipping ignored issue: {issue_id}")
                    continue
                
                # Clean up related_logs to ensure they are strings and valid SHA256s
                related_logs = issue_data.get('related_logs', [])
                cleaned_logs = []
                for log_ref in related_logs:
                    if isinstance(log_ref, str) and len(log_ref) >= 8:  # Valid SHA256 should be longer
                        cleaned_logs.append(log_ref)
                    elif isinstance(log_ref, dict) and 'sha256' in log_ref:
                        cleaned_logs.append(log_ref['sha256'])
                
                issue_data['related_logs'] = cleaned_logs
                issue = Issue(id=issue_id, timestamp=datetime.now().isoformat(), **issue_data).model_dump()
                new_issues.append(issue)
                existing_signatures.add(issue_signature)  # Prevent duplicates within this batch
                
            except Exception as e:
                logging.error(f"Error processing issue: {e}, issue_data: {issue_data}")
                continue
        
        # Update dashboard with new unique issues
        existing_issue_ids = {i['id'] for i in dashboard_data["issues"]}
        truly_new_issues = []
        
        for issue in new_issues:
            if issue['id'] not in existing_issue_ids:
                dashboard_data["issues"].insert(0, issue)
                truly_new_issues.append(issue)
        
        # Maintain max issues limit
        dashboard_data["issues"] = dashboard_data["issues"][:settings["max_issues"]]
        dashboard_data["stats"]["anomalies"] = len(dashboard_data["issues"])
        await save_dashboard_data()
        
        logging.info(f"AI analysis complete. Found {len(truly_new_issues)} new unique issues (filtered {len(new_issues) - len(truly_new_issues)} duplicates).")
        
    except Exception as e:
        logging.error(f"Error during AI analysis: {e}", exc_info=True)
        dashboard_data["summary"] = f"AI analysis failed: {str(e)}"
        set_app_status(f"Analysis error: {str(e)[:30]}")
        await save_dashboard_data()

def update_dashboard_metrics(logs):
    now = datetime.now()
    trend = dashboard_data.get("log_trend", [])
    current_minute = now.strftime("%H:%M")
    
    if trend and trend[-1]["time"] == current_minute:
        trend[-1]["count"] += len(logs)
    else:
        trend.append({"time": current_minute, "count": len(logs)})
    
    dashboard_data["log_trend"] = trend[-60:]
    
    # Update rule distribution
    dist = dashboard_data.get("rule_distribution", {})
    for log in logs:
        rule_desc = log.get("rule", {}).get("description", "Unknown Rule")
        dist[rule_desc] = dist.get(rule_desc, 0) + 1
# --- Background Worker ---
def background_worker():
    """Background worker thread"""
    print("!!! BACKGROUND WORKER FUNCTION CALLED !!!")
    logging.info("!!! BACKGROUND WORKER FUNCTION CALLED !!!")
    
    try:
        print("Background worker starting...")
        logging.info("Background worker starting...")
        set_app_status("Starting up...")
        
        print("Initializing vector database...")
        set_app_status("Loading vector database...")
        initialize_vector_db()
        print("Vector database initialized.")
        
        print("Creating event loop...")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        print("Event loop created.")
        
        print("Loading dashboard data...")
        set_app_status("Loading dashboard data...")
        loop.run_until_complete(load_dashboard_data())
        print("Dashboard data loaded.")
        
        print("Loading settings...")
        load_settings()
        print("Settings loaded.")
        
        print("Loading ignored issues...")
        load_ignored_issues()
        print("Ignored issues loaded.")
        
        set_app_status("Ready")
        logging.info("Background worker initialized successfully.")
        print("Background worker initialized successfully.")
        
        cycle_count = 0
        while True:
            cycle_count += 1
            cycle_start = time.time()
            try:
                logging.info(f"=== Worker cycle {cycle_count} started ===")
                print(f"=== Worker cycle {cycle_count} started at {datetime.now()} ===")
                
                set_app_status("Processing logs...")
                new_logs = loop.run_until_complete(process_logs())
                print(f"Processed logs, found {len(new_logs) if new_logs else 0} new logs")
                
                set_app_status("Updating metrics...")
                update_dashboard_metrics(new_logs)
                print("Updated dashboard metrics")
                
                if new_logs:
                    logging.info(f"Analyzing {len(new_logs)} new logs...")
                    print(f"Analyzing {len(new_logs)} new logs...")
                    set_app_status("AI analyzing logs...")
                    loop.run_until_complete(analyze_context_and_identify_issues(new_logs))
                    print("Analysis complete")
                else:
                    logging.info("No new logs to analyze")
                    print("No new logs to analyze")
                
                dashboard_data["last_run"] = datetime.now().isoformat()
                set_app_status("Saving data...")
                loop.run_until_complete(save_dashboard_data())
                print("Saved dashboard data")
                
                set_app_status("Idle")
                
            except Exception as e:
                logging.error(f"Error in background worker cycle {cycle_count}: {e}", exc_info=True)
                print(f"ERROR in background worker cycle {cycle_count}: {e}")
                dashboard_data["summary"] = f"Worker Error: {e}"
                set_app_status(f"Error: {str(e)[:50]}")
                loop.run_until_complete(save_dashboard_data())
            
            cycle_time = time.time() - cycle_start
            loop.run_until_complete(metrics.set_cycle_time(cycle_time))
            
            logging.info(f"=== Worker cycle {cycle_count} finished in {cycle_time:.2f}s ===")
            print(f"=== Worker cycle {cycle_count} finished in {cycle_time:.2f}s ===")
            print(f"Sleeping for {settings['processing_interval']} seconds...")
            time.sleep(settings['processing_interval'])
            
    except Exception as e:
        logging.error(f"Fatal error in background worker: {e}", exc_info=True)
        print(f"FATAL: Background worker crashed: {e}")
        set_app_status("Fatal error - worker crashed")
        import traceback
        traceback.print_exc()

# --- FastAPI App ---
def check_auth(credentials: HTTPBasicCredentials = Depends(security)):
    is_user_ok = credentials.username == BASIC_AUTH_USER
    is_pass_ok = credentials.password == BASIC_AUTH_PASS
    if not (is_user_ok and is_pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

@app.get("/", response_class=HTMLResponse)
async def get_dashboard_ui(user: str = Depends(check_auth)):
    return HTMLResponse(content=HTML_CONTENT)

@app.get("/api/dashboard", response_model=DashboardData)
async def get_dashboard_data_api(user: str = Depends(check_auth)):
    # Include settings for countdown timer
    dashboard_data["settings"] = {"processing_interval": settings["processing_interval"]}
    return dashboard_data

@app.get("/api/logs/{log_id}")
async def get_log_details(log_id: str, user: str = Depends(check_auth)):
    async with vector_lock:
        log = metadata_db.get(log_id)
    if not log: 
        raise HTTPException(status_code=404, detail="Log not found")
    
    escaped_log = json.loads(json.dumps(log).replace('<', '&lt;').replace('>', '&gt;'))
    return JSONResponse(content=escaped_log)

@app.get("/metrics", response_class=PlainTextResponse)
async def get_metrics():
    """Prometheus-style metrics endpoint (no auth required)"""
    return await metrics.get_metrics_text()

@app.post("/api/chat/analyze")
async def chat_analyze(req: QueryRequest, user: str = Depends(check_auth)):
    """Analyze user query and plan the information gathering strategy"""
    logging.info(f"Analyzing chat query: {req.query}")
    
    # Get basic context about available data
    total_logs = dashboard_data["stats"]["total_logs"]
    recent_issues = len(dashboard_data["issues"])
    
    analysis_prompt = f"""You are a security analyst AI assistant. A user has asked a question about their security logs and issues. Your job is to analyze their query and determine what information you need to gather to provide a comprehensive answer.

**User Query:** {req.query}

**Available Data Context:**
- Total indexed logs: {total_logs:,}
- Current security issues: {recent_issues}
- Vector database with full log history available
- Real-time security issue tracking

**Your Task:**
Analyze the user's query and determine:
1. What specific information you need to search for
2. What search queries would be most effective
3. Whether you need current issues, historical logs, or both

Respond with a JSON object containing your analysis plan:
{{
  "search_strategy": "brief description of your approach",
  "search_queries": ["query1", "query2", "query3"],
  "need_issues": true/false,
  "focus_areas": ["area1", "area2"],
  "estimated_complexity": "simple|moderate|complex"
}}

Examples of good search queries:
- "failed login attempts brute force"
- "suspicious network connections"
- "malware detection alerts"
- "privilege escalation attempts"
- "unusual file access patterns"

Respond ONLY with the JSON object."""

    try:
        response = await call_gemini_api(analysis_prompt, is_json_output=True, model_name=LITE_MODEL)
        analysis = json.loads(response)
        
        # Validate the response structure
        if not isinstance(analysis, dict) or "search_queries" not in analysis:
            raise ValueError("Invalid analysis response structure")
            
        return JSONResponse(content=analysis)
        
    except Exception as e:
        logging.error(f"Chat analysis failed: {e}")
        # Fallback analysis
        fallback = {
            "search_strategy": "General search approach due to analysis error",
            "search_queries": [req.query],
            "need_issues": True,
            "focus_areas": ["general security"],
            "estimated_complexity": "simple"
        }
        return JSONResponse(content=fallback)

@app.post("/api/chat/execute") 
async def chat_execute(request: dict, user: str = Depends(check_auth)):
    """Execute the planned searches and generate final response"""
    query = request.get("query", "")
    analysis = request.get("analysis", {})
    history = request.get("history", [])
    
    logging.info(f"Executing chat plan for query: {query}")
    
    try:
        # Step 1: Search for relevant issues if needed
        issue_context = []
        if analysis.get("need_issues", False) and dashboard_data["issues"]:
            logging.info("Gathering relevant security issues...")
            recent_issues = dashboard_data["issues"][:10]
            for issue in recent_issues:
                # Simple relevance check
                if any(word.lower() in issue["title"].lower() or word.lower() in issue["summary"].lower() 
                       for word in query.lower().split()):
                    issue_context.append({
                        "title": issue["title"],
                        "severity": issue["severity"], 
                        "summary": issue["summary"][:300],
                        "timestamp": issue["timestamp"]
                    })
            issue_context = issue_context[:5]  # Limit to 5 most relevant
        
        # Step 2: Execute vector database searches
        all_search_results = []
        search_queries = analysis.get("search_queries", [query])[:3]  # Max 3 searches
        
        for i, search_query in enumerate(search_queries):
            logging.info(f"Executing search {i+1}/{len(search_queries)}: {search_query}")
            try:
                results = await search_vector_db(search_query, k=15)  # Smaller k for chat
                for result in results:
                    log_data = result.get('metadata', {})
                    # Compact log representation
                    compact_log = {
                        "timestamp": log_data.get("timestamp", ""),
                        "rule": log_data.get("rule", {}).get("description", "")[:100],
                        "level": log_data.get("rule", {}).get("level", ""),
                        "agent": log_data.get("agent", {}).get("name", ""),
                        "sha256": log_data.get("sha256", "")[:8]
                    }
                    # Add specific data if relevant
                    if "data" in log_data and log_data["data"]:
                        compact_log["data"] = str(log_data["data"])[:150]
                    
                    all_search_results.append(compact_log)
                    
                    if len(all_search_results) >= 20:  # Total limit across all searches
                        break
                        
            except Exception as e:
                logging.error(f"Search failed for query '{search_query}': {e}")
                continue
        
        # Step 3: Generate comprehensive response
        logging.info("Generating AI response with gathered context...")
        
        # Prepare context strings
        issue_context_str = json.dumps(issue_context, indent=1) if issue_context else "[]"
        logs_context_str = json.dumps(all_search_results, indent=1) if all_search_results else "[]"
        
        # Include conversation history
        history_str = ""
        if history:
            history_str = "\n".join([
                f"User: {h.get('user', '')[:100]}\nAI: {h.get('ai', '')[:200]}" 
                for h in history[-2:]
            ])
        
        final_prompt = f"""You are an expert security analyst AI assistant. Based on the comprehensive data gathered, provide a thorough and helpful response to the user's question.

**User Question:** {query}

**Recent Conversation:**
{history_str}

**Search Strategy Used:** {analysis.get('search_strategy', 'Standard search')}

**Relevant Security Issues Found:**
{issue_context_str}

**Relevant Log Data Found ({len(all_search_results)} entries):**
{logs_context_str}

**Instructions:**
1. Provide a comprehensive answer to the user's question
2. Reference specific findings from the issues and logs
3. Include relevant timestamps, severity levels, and log IDs where helpful
4. If patterns or trends are visible, explain them
5. Provide actionable insights or recommendations
6. If insufficient data was found, explain what additional information might be helpful
7. Keep the response well-structured and easy to read
8. Cite specific SHA256 hashes when referencing logs

**Response Guidelines:**
- Be conversational but professional
- Focus on security implications
- Highlight the most important findings first
- Use bullet points or numbered lists for clarity when appropriate
- Maximum response length: 500 words"""

        # Token count check
        token_count = count_tokens_local(final_prompt, PRO_MODEL)
        logging.info(f"Final response prompt token count: {token_count}")
        
        if token_count > 80_000:  # Conservative limit for chat
            # Reduce context if too large
            logs_context_str = json.dumps(all_search_results[:10], indent=1)
            issue_context_str = json.dumps(issue_context[:3], indent=1)
            
            final_prompt = f"""You are a security analyst AI assistant. Answer the user's question based on available data.

**User Question:** {query}

**Security Issues:** {issue_context_str}

**Log Data (sample):** {logs_context_str}

Provide a helpful, concise response focusing on the most relevant security findings. Include specific log references where possible."""

        response = await call_gemini_api(final_prompt, model_name=PRO_MODEL)
        
        logging.info("Chat execution completed successfully")
        return JSONResponse(content={"answer": response})
        
    except Exception as e:
        logging.error(f"Chat execution failed: {e}")
        return JSONResponse(content={
            "answer": f"I encountered an error while analyzing your request: {str(e)}. Please try rephrasing your question or contact support if the issue persists."
        }, status_code=500)

@app.post("/api/analyze")
async def manual_analyze(user: str = Depends(check_auth)):
    logging.info("Manual analysis triggered")
    try:
        new_logs = await process_logs()
        update_dashboard_metrics(new_logs)
        if new_logs:
            await analyze_context_and_identify_issues(new_logs)
        dashboard_data["last_run"] = datetime.now().isoformat()
        await save_dashboard_data()
        logging.info("Manual analysis completed")
        return {"status": "Analysis triggered"}
    except Exception as e:
        logging.error(f"Manual analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/issues/{issue_id}/ignore")
async def ignore_issue(issue_id: str, user: str = Depends(check_auth)):
    # Remove from current issues
    dashboard_data["issues"] = [i for i in dashboard_data["issues"] if i["id"] != issue_id]
    
    # Add to persistent ignore list
    ignored_issue_ids.add(issue_id)
    
    # Update stats
    dashboard_data["stats"]["anomalies"] = len(dashboard_data["issues"])
    
    # Save everything
    await save_dashboard_data()
    save_ignored_issues()
    
    logging.info(f"Issue {issue_id} ignored and added to persistent ignore list")
    return {"status": "Issue ignored"}

@app.post("/api/issues/{issue_id}/query")
async def query_issue(issue_id: str, req: QueryRequest, user: str = Depends(check_auth)):
    issue = next((i for i in dashboard_data["issues"] if i["id"] == issue_id), None)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    async with vector_lock:
        related_logs = [metadata_db.get(log_id) for log_id in issue["related_logs"][:10] if metadata_db.get(log_id)]
    
    log_context_str = json.dumps(related_logs)
    history_str = "\n".join([f"User: {h['user']}\nAI: {h['ai']}" for h in req.history[-2:]]) if req.history else ""
    
    prompt = f"""You are a helpful security analyst assistant. A user is asking a question about a specific security issue. Use the conversation history for context.

**Issue Details:**
Title: {issue["title"]}
Summary: {issue["summary"]}
Recommendation: {issue["recommendation"]}

**Conversation History:**
{history_str}

**User Question:**
{req.query}

**Relevant Raw Log Context (JSON Array):**
```json
{log_context_str}
```

**Instructions:**
- Answer the user's question directly and concisely based on the issue details, provided log data, and history.
- Cite specific Log SHA256 hashes that support your answer.
- If the provided context does not contain enough information, state that clearly.
- Present the answer in a clear, readable format.
"""
    
    try:
        answer = await call_gemini_api(prompt, model_name=PRO_MODEL)
        return JSONResponse(content={"answer": answer})
    except HTTPException as e:
        return JSONResponse(content={"answer": f"Error communicating with AI: {e.detail}"}, status_code=e.status_code)

@app.post("/api/issues/{issue_id}/generate-script")
async def generate_script(issue_id: str, user: str = Depends(check_auth)):
    issue = next((i for i in dashboard_data["issues"] if i["id"] == issue_id), None)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    # Get related logs for context
    async with vector_lock:
        related_logs = [metadata_db.get(log_id) for log_id in issue["related_logs"][:5] if metadata_db.get(log_id)]
    
    log_context_str = json.dumps(related_logs, indent=2)
    
    prompt = f"""You are an expert security engineer. Generate a comprehensive diagnosis and automatic repair script for the following security issue.

**Issue Details:**
Title: {issue["title"]}
Severity: {issue["severity"]}
Summary: {issue["summary"]}
Current Recommendation: {issue["recommendation"]}

**Related Logs (for context):**
```json
{log_context_str}
```

**Instructions:**
1. Create a bash script that performs the following:
   - Initial diagnosis commands to verify the issue
   - Backup any configurations that will be modified
   - Step-by-step remediation actions
   - Verification commands to confirm the issue is resolved
   - Rollback procedure if something goes wrong

2. The script should:
   - Be safe and include error handling
   - Log all actions to /var/log/wazuh_repair_$(date +%Y%m%d_%H%M%S).log
   - Request confirmation before making critical changes
   - Be compatible with common Linux distributions (Ubuntu, CentOS, RHEL)
   - Include comments explaining each step
   - Be limited to 200 lines maximum

3. Focus on:
   - The specific issue identified
   - The systems/IPs/users mentioned in the logs
   - Wazuh-specific configurations if relevant
   - System hardening based on the attack vector

Output ONLY the complete bash script, starting with #!/bin/bash."""

    try:
        script = await call_gemini_api(prompt, model_name=PRO_MODEL)
        # Clean up the script
        if "```bash" in script:
            script = script.split("```bash", 1)[-1].rsplit("```", 1)[0].strip()
        elif "```" in script:
            script = script.split("```", 1)[-1].rsplit("```", 1)[0].strip()
        
        if not script.startswith("#!/bin/bash"):
            script = "#!/bin/bash\n" + script
        
        lines = script.split('\n')
        if len(lines) > 200:
            script = '\n'.join(lines[:200]) + '\n# Script truncated to 200 lines for safety'
        
        safety_disclaimer = """#!/bin/bash
# SAFETY DISCLAIMER: This script was auto-generated by AI.
# Please review carefully before execution. Test in a safe environment first.
# The script may need adjustments for your specific environment.

"""
        if not "SAFETY DISCLAIMER" in script:
            script = script.replace("#!/bin/bash", safety_disclaimer, 1)
            
        return JSONResponse(content={"script": script})
    except HTTPException as e:
        return JSONResponse(content={"script": f"# Error generating script: {e.detail}"}, status_code=e.status_code)

@app.get("/api/settings")
async def get_settings(user: str = Depends(check_auth)):
    return settings

@app.post("/api/settings")
async def update_settings(new_settings: Settings, user: str = Depends(check_auth)):
    settings.update({k: v for k, v in new_settings.dict().items() if v is not None})
    save_settings()
    return {"status": "Settings updated"}

@app.post("/api/clear_db")
async def api_clear_database(user: str = Depends(check_auth)):
    await clear_database()
    return {"status": "Database cleared"}

if __name__ == "__main__":
    if not GEMINI_API_KEYS:
        print("="*80)
        print("!!! CRITICAL ERROR: No GEMINI_API_KEY environment variables are set. !!!")
        print("!!! The application cannot start without at least one.                  !!!")
        print("!!! Please set one or more of the following:                           !!!")
        print("!!! export GEMINI_API_KEY='your_api_key_here'                          !!!")
        print("!!! export GEMINI_API_KEY_2='your_second_api_key_here'                 !!!")
        print("!!! export GEMINI_API_KEY_3='your_third_api_key_here'                  !!!")
        print("="*80)
        exit(1)
    
    if not BASIC_AUTH_USER or not BASIC_AUTH_PASS:
        print("="*80)
        print("!!! CRITICAL ERROR: Authentication credentials not set.                 !!!")
        print("!!! Please set the following environment variables:                     !!!")
        print("!!! export BASIC_AUTH_USER='your_username'                              !!!")
        print("!!! export BASIC_AUTH_PASS='your_password'                              !!!")
        print("="*80)
        exit(1)
    
    os.makedirs(DB_DIR, exist_ok=True)

    print("--- Starting Wazuh Threat Hunter Pro (Gemini Edition) ---")
    print(f"Dashboard will be available at: http://0.0.0.0:8000")
    print(f"Username: {BASIC_AUTH_USER}")
    print(f"Password: [hidden]")
    print(f"Loaded {len(GEMINI_API_KEYS)} Gemini API keys")
    print(f"Metrics available at: http://0.0.0.0:8000/metrics")
    print("---------------------------------------------------------")
    
    # Add a test to see if lifespan events work
    print("🧪 Testing if lifespan events are supported...")
    
    # BACKUP PLAN: If lifespan doesn't work, start worker manually
    def start_backup_worker():
        print("⚠️  Lifespan events may not be working. Starting backup worker...")
        logging.info("⚠️  Lifespan events may not be working. Starting backup worker...")
        
        try:
            worker_thread = threading.Thread(target=background_worker, daemon=True, name="BackupThreatHunterWorker")
            worker_thread.start()
            print(f"✅ Backup worker thread started. Alive: {worker_thread.is_alive()}")
            logging.info(f"✅ Backup worker thread started. Alive: {worker_thread.is_alive()}")
            return worker_thread
        except Exception as e:
            print(f"❌ Failed to start backup worker: {e}")
            logging.error(f"❌ Failed to start backup worker: {e}")
            return None
    
    # Start backup worker after a delay to see if lifespan works
    def delayed_backup_start():
        time.sleep(5)  # Wait 5 seconds
        print("🔍 Checking if lifespan handler started the worker...")
        
        # Check if any ThreatHunterWorker threads exist
        threat_hunter_threads = [t for t in threading.enumerate() if 'ThreatHunter' in t.name]
        
        if not threat_hunter_threads:
            print("❌ No ThreatHunter worker threads found. Starting backup worker...")
            start_backup_worker()
        else:
            print(f"✅ Found {len(threat_hunter_threads)} ThreatHunter threads: {[t.name for t in threat_hunter_threads]}")
    
    # Start the backup check in a separate thread
    backup_thread = threading.Thread(target=delayed_backup_start, daemon=True, name="BackupChecker")
    backup_thread.start()
    
    print("🚀 Starting uvicorn server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)