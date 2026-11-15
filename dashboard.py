
import streamlit as st
import sqlite3
import pandas as pd

st.set_page_config(
    page_title="DNS Tunnel Detection",
    layout="wide"
)

st.title("DNS Tunnel Detection - Findings")

if st.button("Refresh"):
    st.rerun()

conn = sqlite3.connect("incidents.db")

conn.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT,
        qname TEXT,
        length INTEGER,
        entropy REAL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
""")

conn.commit()

df = pd.read_sql_query(
    "SELECT * FROM incidents ORDER BY id DESC LIMIT 20",
    conn
)

conn.close()

if df.empty:
    st.info("No incidents yet. Run the detector against an authorized PCAP file.")
else:
    st.subheader("Recent Detection Incidents")
    st.dataframe(df, use_container_width=True)
