
-- --------------------------------------------------------

--
-- Table structure for table `user_login_attempt`
--

CREATE TABLE `user_login_attempt` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `success` tinyint(1) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
