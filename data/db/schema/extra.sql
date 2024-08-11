
--
-- Indexes for dumped tables
--

--
-- Indexes for table `user`
--
ALTER TABLE `user`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `user_name` (`username`);

--
-- Indexes for table `user_activation_token`
--
ALTER TABLE `user_activation_token`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `user_login_attempt`
--
ALTER TABLE `user_login_attempt`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `user_password_reset`
--
ALTER TABLE `user_password_reset`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `user`
--
ALTER TABLE `user`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `user_activation_token`
--
ALTER TABLE `user_activation_token`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `user_login_attempt`
--
ALTER TABLE `user_login_attempt`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `user_password_reset`
--
ALTER TABLE `user_password_reset`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
