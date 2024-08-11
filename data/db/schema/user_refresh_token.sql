
-- --------------------------------------------------------

--
-- Table structure for table `user_refresh_token`
--

CREATE TABLE `user_refresh_token` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `token` int(11) NOT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `revoked` tinyint(1) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
