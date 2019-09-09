import React, { useState, useContext } from "react";
import {
  Collapse,
  Navbar,
  NavbarToggler,
  NavbarBrand,
  Nav,
  NavItem,
  NavLink,
} from "reactstrap";
import { NavLink as LinkNav } from "react-router-dom";
import { UserContext } from "../Contexts/UserContext";

const AppNavBar = props => {
  const { isLogin, setIsLogin } = useContext(UserContext);

  const [isOpen, setIsOpen] = useState(false);

  const toggle = () => {
    setIsOpen(!isOpen);
  };

  const goHome = () => {
    props.history.push("/");
  };

  const onLogout = () => {
    setIsLogin(false);
    localStorage.removeItem("token");
  };

  return (
    <div>
      <Navbar color="dark" dark expand="sm">
        <NavbarBrand onClick={goHome} className="logo">
          reactstrap
        </NavbarBrand>
        <NavbarToggler onClick={toggle} />
        <Collapse isOpen={isOpen} navbar>
          <Nav className="ml-auto" navbar>
            {isLogin ? (
              <NavItem>
                <LinkNav to={"/profile"} className="nav-link">
                  Profile
                </LinkNav>
              </NavItem>
            ) : (
              <NavItem>
                <LinkNav to={"/login"} className="nav-link">
                  Login
                </LinkNav>
              </NavItem>
            )}

            <NavItem>
              <NavLink onClick={goHome}>GitHub</NavLink>
            </NavItem>
            {isLogin ? (
              <NavItem>
                <LinkNav onClick={onLogout} className="nav-link">
                  Logout
                </LinkNav>
              </NavItem>
            ) : (
              ""
            )}
          </Nav>
        </Collapse>
      </Navbar>
    </div>
  );
};

export default AppNavBar;
