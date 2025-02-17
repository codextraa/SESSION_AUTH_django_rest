"use client";
import styles from "./Sidebar.module.css";


export default function Sidebar({ onFilterChange, isFiltered, isReset, currentGroup, currentStatus, currentPageSize }) {
  return (
    <div className={styles.sidebar}>
      <div className={styles.filterGroup}>
        <h3>User Group</h3>
        <select value={currentGroup} onChange={(e) => onFilterChange("group", e.target.value)} className={styles.select}>
          <option value="">All</option>
          <option value="Default">Users</option>
          <option value="Admin">Admins</option>
          <option value="Superuser">Superusers</option>
        </select>
      </div>
      <div className={styles.filterGroup}>
        <h3>User Status</h3>
        <select value={currentStatus} onChange={(e) => onFilterChange("is_active", e.target.value)} className={styles.select}>
          <option value="">All</option>
          <option value="true">Active</option>
          <option value="false">Inactive</option>
        </select>
      </div>
      <div className={styles.filterGroup}>
        <h3>Page Size</h3>
        <select value={currentPageSize} onChange={(e) => onFilterChange("page_size", e.target.value)} className={styles.select}>
          <option value="0">Default</option>
          <option value="10">10</option>
          <option value="20">20</option>
          <option value="50">50</option>
        </select>
      </div>
      {(isFiltered || currentGroup || currentStatus || currentPageSize != "0") && (
        <button onClick={isReset} className={styles.showAllButton}>
          Reset Filter
        </button>
      )}
    </div>
  );
};