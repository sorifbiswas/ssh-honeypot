"""Streamlit dashboard. Run: streamlit run dashboard/app.py"""
import os
import sqlite3

import pandas as pd
import streamlit as st

DB_PATH = os.environ.get("HONEYPOT_DB", "data/honeypot.db")

st.set_page_config(page_title="SSH Honeypot", layout="wide")
st.title("SSH Honeypot Dashboard")

if not os.path.exists(DB_PATH):
    st.warning(f"No database found at {DB_PATH}. Start the honeypot first.")
    st.stop()


@st.cache_data(ttl=30)
def q(sql):
    with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) as conn:
        return pd.read_sql_query(sql, conn)


auth = q("SELECT * FROM auth_attempts")
cmds = q("SELECT * FROM commands")
info = q("SELECT * FROM ip_info")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Login attempts", len(auth))
c2.metric("Unique attacker IPs", auth["ip"].nunique() if len(auth) else 0)
c3.metric("Unique usernames", auth["username"].nunique() if len(auth) else 0)
c4.metric("Commands captured", len(cmds))

if len(auth):
    auth["ts"] = pd.to_datetime(auth["ts"])
    st.subheader("Attempts over time (per hour)")
    st.line_chart(auth.set_index("ts").resample("1h").size())

    left, right = st.columns(2)
    left.subheader("Top usernames")
    left.bar_chart(auth["username"].value_counts().head(15))
    right.subheader("Top passwords")
    right.bar_chart(auth["password"].value_counts().head(15))

    st.subheader("Top attacker IPs")
    top = auth["ip"].value_counts().head(20).rename("attempts").reset_index()
    top.columns = ["ip", "attempts"]
    if len(info):
        top = top.merge(info[["ip", "country", "org"]], on="ip", how="left")
    st.dataframe(top)

    if len(info):
        st.subheader("Attempts by country")
        merged = auth.merge(info[["ip", "country"]], on="ip", how="left")
        st.bar_chart(merged["country"].fillna("Unknown").value_counts().head(15))
    else:
        st.info("Run `python -m honeypot.enrich` to add country/ASN data.")

if len(cmds):
    st.subheader("Recent commands")
    st.dataframe(cmds.sort_values("ts", ascending=False).head(100))
