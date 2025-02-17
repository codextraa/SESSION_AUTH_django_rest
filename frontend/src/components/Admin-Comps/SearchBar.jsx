"use client";
import { useState, useEffect } from "react";
import styles from "./SearchBar.module.css";


export default function SearchBar({ onSearch, currentSearch }) {
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    setSearchTerm(currentSearch);
  }, [currentSearch]);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSearch(searchTerm);
  };

  return (
    <form onSubmit={handleSubmit} className={styles.searchForm}>
      <input
        type="text"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        placeholder="Search users..."
        className={styles.searchInput}
      />
      <button type="submit" className={styles.searchButton}>
        Search
      </button>
    </form>
  );
};
