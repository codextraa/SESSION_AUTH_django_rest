"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { BASE_ROUTE } from "@/route";
import { 
  getUsersAction, 
  deleteUserAction, 
  activateUserAction, 
  deactivateUserAction 
} from "@/actions/userActions";
import { getUserRoleAction } from "@/actions/authActions";
import SearchBar from "@/components/Admin-Comps/SearchBar";
import Sidebar from "@/components/Admin-Comps/Sidebar";
import UserCard from "@/components/Cards/UserCard";
import Pagination from "@/components/Admin-Comps/Pagination";
import styles from "./page.module.css";


export default function AdminDashboard() {
  const [users, setUsers] = useState([]);
  const [pagination, setPagination] = useState(null);
  const [filters, setFilters] = useState({
    search: "",
    group: "",
    is_active: "",
    page: 1,
    page_size: "0",
  });
  const [userRole, setUserRole] = useState(null);
  const [noUser, setNoUser] = useState(false);
  const [loading, setLoading] = useState(false);
  const [isFiltered, setIsFiltered] = useState(false);
  const [currentSearch, setCurrentSearch] = useState("");
  const [currentGroup, setCurrentGroup] = useState("");
  const [currentStatus, setCurrentStatus] = useState("");
  const [currentPageSize, setCurrentPageSize] = useState("0");
  const [successMessage, setSuccessMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    const fetchUserRole = async () => {
      const role = await getUserRoleAction();
      setUserRole(role);
    };
    fetchUserRole();
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [filters.page, filters.page_size, filters.search, filters.group, filters.is_active]);

  const fetchUsers = async () => {
    try {
      const result = await getUsersAction(filters);
      if (result.data) {
        if (result.data.length === 0) {
          setNoUser(true);
        } else {
          setUsers(result.data);
          setNoUser(false);
          setPagination(result.pagination);
        };
      } else if (result.error) {
        setErrorMessage(result.error);
      };
    } catch (error) {
      setErrorMessage("Failed to fetch users.");
    };
    setLoading(false);
  };

  const handleSearch = (searchTerm) => {
    if (searchTerm === currentSearch) return;
    setLoading(true);
    setNoUser(false);
    setFilters((prev) => ({ ...prev, search: searchTerm, page: 1 }));
    setCurrentSearch(searchTerm);
    if (searchTerm === "") {
      setIsFiltered(false);
    } else {
      setIsFiltered(true);
    };
  };

  const handleFilterChange = (filterName, value) => {
    setLoading(true);
    setNoUser(false);
    setFilters((prev) => ({ ...prev, [filterName]: value, page: 1 }));
    switch (filterName) {
      case "group":
        setCurrentGroup(value);
        break;
      case "is_active":
        setCurrentStatus(value);
        break;
      case "page_size":
        setCurrentPageSize(value);
        break;
    };
  };

  const handlePageChange = (newPage) => {
    setLoading(true);
    setNoUser(false);
    setFilters((prev) => ({ ...prev, page: newPage }));
  };

  const handleResetFilter = () => {
    setLoading(true);
    setNoUser(false);
    setFilters({
      search: "",
      group: "",
      is_active: "",
      page: 1,
      page_size: "0",
    });
    setIsFiltered(false);
    setCurrentSearch("");
    setCurrentGroup("");
    setCurrentStatus("");
    setCurrentPageSize("0");
  };

  const handleAction = async (action, id) => {
    let updateUser = true;

    if (pagination.total_pages !== 1 && 
      filters.page === pagination.total_pages && 
      users.length === 1) {
      setFilters((prev) => ({ ...prev, page: prev.page - 1 }));
      updateUser = false; // prevent double fetchUser call
    };

    if (action === "activate") {
      await handleActivate(id);
    } else if (action === "deactivate") {
      await handleDeactivate(id);
    } else if (action === "delete") {
      await handleDelete(id);
    };

    if (updateUser) {
      fetchUsers();
    };
    clearMessages();
  };

  const handleActivate = async (id) => {
    try {
      const result = await activateUserAction(id);
      if (result.success) {
        setSuccessMessage(result.success);
      } else if (result.error) {
        setErrorMessage(result.error);
      };
    } catch (error) {
      setErrorMessage("Failed to activate user.");
    };
  };

  const handleDeactivate = async (id) => {
    try {
      const result = await deactivateUserAction(id);
      if (result.success) {
        setSuccessMessage(result.success);
      } else if (result.error) {
        setErrorMessage(result.error);
      };
    } catch (error) {
      setErrorMessage("Failed to deactivate user.");
    };
  };

  const handleDelete = async (id) => {
    try {
      const result = await deleteUserAction(id);
      if (result.success) {
        setSuccessMessage(result.success);
      } else if (result.error) {
        setErrorMessage(result.error);
      };
    } catch (error) {
      setErrorMessage("Failed to delete user.");
    };
  };

  const clearMessages = () => {
    setTimeout(() => {
      setSuccessMessage("");
      setErrorMessage("");
    }, 5000);
  };

  if (userRole !== "Admin" && userRole !== "Superuser") {
    return <div>Access Denied. You must be an Admin or Superuser to view this page.</div>
  };

  if (noUser || loading) {
    return (
      <div className={styles.dashboard}>
        <Sidebar 
        onFilterChange={handleFilterChange} 
        isFiltered={isFiltered} 
        isReset={handleResetFilter}
        currentGroup={currentGroup}
        currentStatus={currentStatus}
        currentPageSize={currentPageSize}
        />
        <div className={styles.content}>
          <h1>Admin Dashboard</h1>
          <div className={styles.controls}>
            <SearchBar 
            onSearch={handleSearch}
            currentSearch={currentSearch}
            />
            {userRole === "Superuser" && 
            <Link href={`${BASE_ROUTE}/admin-dashboard/new-admin`} className={styles.newAdmin}>
              Create New Admin
            </Link>}
          </div>
          {successMessage && <div className={styles.successMessage}>{successMessage}</div>}
          {errorMessage && <div className={styles.errorMessage}>{errorMessage}</div>}
          {noUser && 
          <div className={styles.userGrid}>
            <p>No users found.</p>
          </div>}
          {loading && 
          <div className={styles.userGrid}>
            <p>Loading...</p>
          </div>}
        </div>
      </div>
    );
  };

  return (
    <div className={styles.dashboard}>
      <Sidebar 
      onFilterChange={handleFilterChange} 
      isFiltered={isFiltered} 
      isReset={handleResetFilter}
      currentGroup={currentGroup}
      currentStatus={currentStatus}
      currentPageSize={currentPageSize}
      />
      <div className={styles.content}>
        <h1>Admin Dashboard</h1>
        <div className={styles.controls}>
          <SearchBar 
          onSearch={handleSearch}
          currentSearch={currentSearch}
          />
          {userRole === "Superuser" && 
          <Link href={`${BASE_ROUTE}/admin-dashboard/new-admin`} className={styles.newAdmin}>
            Create New Admin
          </Link>}
        </div>
        {successMessage && <div className={styles.successMessage}>{successMessage}</div>}
        {errorMessage && <div className={styles.errorMessage}>{errorMessage}</div>}
        <div className={styles.userGrid}>
          {users.map((user) => (
            <UserCard
              key={user.id}
              user={user}
              userRole={userRole}
              onAction={handleAction}
            />
          ))}
        </div>
        {pagination && (
          <Pagination
            currentPage={filters.page}
            totalPages={pagination.total_pages}
            onPageChange={handlePageChange}
          />
        )}
      </div>
    </div>
  );
};
