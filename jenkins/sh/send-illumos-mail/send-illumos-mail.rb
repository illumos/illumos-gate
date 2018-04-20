#!/usr/bin/env ruby

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2017 by Delphix. All rights reserved.
#

require 'octokit'
require 'optparse'
require 'ostruct'
require 'mail'

MAIL_TO = "developer@lists.illumos.org"

SEND_MAIL_LABEL_NAME = "please send illumos mail"
MAIL_SENT_LABEL_NAME = "illumos mail has been sent"

def get_options()
    options = OpenStruct.new

    options.netrc_file = nil
    options.repository = nil
    options.user = nil
    options.password = nil

    OptionParser.new do |opts|
        opts.on('--netrc-file FILE') do |file|
            options.netrc_file = file
        end
        opts.on('--repository REPO') do |repo|
            options.repository = repo
        end
        opts.on('--smtp-user USER') do |user|
            options.user = user
        end
        opts.on('--smtp-password PASSWORD') do |password|
            if password == "-"
                options.password = STDIN.gets()
            else
                options.password = password
            end
        end
    end.parse!

    if options.netrc_file.nil? or options.repository.nil? or
            options.user.nil? or options.password.nil?
        raise OptionParser::MissingArgument
    end

    return options
end

def fetch_pulls_needing_illumos_mail(client, repo)
    pulls = []

    client.pulls(repo).each do |pull|
        labels = client.labels_for_issue(repo, pull[:number])

        send_mail_label = false
        mail_sent_label = false

        labels.each do |label|
            if label[:name] == SEND_MAIL_LABEL_NAME
                send_mail_label = true
            end

            if label[:name] == MAIL_SENT_LABEL_NAME
                mail_sent_label = true
            end
        end

        if send_mail_label
            if mail_sent_label
                #
                # If we've already sent the mail, then we don't want to
                # send it again. In this case, remove the "send" label,
                # leaving only "sent" label to indicate that the mail has
                # already been sent, and we don't need to send it again.
                #
                # Generally, this case shouldn't happen, since we'll
                # attempt to remove the "send" label right after we send
                # the mail successfully, and add the "sent" label. It's
                # possible, though, that some abnormal event prevented
                # the "send" label from being removed. If that were to
                # occur, we should eventually hit this block (e.g. the
                # next time this script is run) and remove the "send"
                # label.
                #
                remove_send_mail_label(client, repo, pull)
            else
                #
                # If the "sent" label isn't found, then we trust the
                # presence of the "send" label, and proceed to send the
                # mail. Usually this will happen prior to any mail has
                # been sent for the given PR, but can also occur if the
                # labels are manually modified (e.g. by removing the
                # "sent" label and adding the "send" label, to
                # intentionally cause another mail to be sent).
                #
                pulls << pull
            end
        end
    end

    return pulls
end

def get_mail_subject(client, repo, pull)
    return pull[:title]
end

def get_mail_body(client, repo, pull)
    body = []
    body << "Review: " + pull[:html_url]
    body << ""
    body << "Diff: " + pull[:diff_url]
    body << "Patch: " + pull[:patch_url]
    body << ""
    body << pull[:body]
    return body.join("\n")
end

def get_mail_from_name(client, repo, pull)
    name = client.user(pull[:user][:login]).name

    if name.nil?
        return "OpenZFS Bot"
    else
        return name
    end
end

def append_mail_address(list, name, email)
    if email.nil?
        return
    end

    if name.nil?
        list << email
    else
        list << "#{name} <#{email}>"
    end
end

def get_mail_cc(client, repo, pull)
    cc = []

    user = client.user(pull[:user][:login])
    append_mail_address(cc, user[:name], user[:email])

    client.pull_commits(repo, pull[:number]).each do |commit|
        append_mail_address(cc, commit[:commit][:author][:name],
                                commit[:commit][:author][:email])

        append_mail_address(cc, commit[:commit][:committer][:name],
                                commit[:commit][:committer][:email])
    end

    #
    # It's possible, and probably expected, for the commits in a
    # multi-commit pull request, and/or the user/owner of the PR,
    # to have overlapping email addresses. E.g. If a single person
    # authored the change, committed the change, and opened the pull
    # request, we don't want to have 3 identical entries in the list
    # of addresses we CC. Thus, we take the list generated above,
    # filter out duplicate entries, prior to building the CC list.
    #
    return cc.uniq.join(", ")
end

def send_illumos_mail(client, repo, pull, user, password)
    Mail.defaults do
        delivery_method :smtp, :address              => "smtp.gmail.com",
                               :port                 => 587,
                               :domain               => 'gmail.com',
                               :user_name            => user,
                               :password             => password,
                               :authentication       => 'plain',
                               :enable_starttls_auto => true
    end

    mail = Mail.deliver do
        to MAIL_TO.encode(Encoding::UTF_8)
        content_type "text/plain; charset=utf-8".encode(Encoding::UTF_8)
        subject get_mail_subject(client, repo, pull).encode(Encoding::UTF_8)
        from get_mail_from_name(client, repo, pull).encode(Encoding::UTF_8)
        body get_mail_body(client, repo, pull).encode(Encoding::UTF_8)
        cc get_mail_cc(client, repo, pull).encode(Encoding::UTF_8)
    end
end

def remove_send_mail_label(client, repo, pull)
    client.remove_label(repo, pull[:number], SEND_MAIL_LABEL_NAME)
end

def add_mail_sent_label(client, repo, pull)
    client.add_labels_to_an_issue(repo, pull[:number], [MAIL_SENT_LABEL_NAME])
end

def main()
    options = get_options()

    client = Octokit::Client.new(:netrc => true,
            :netrc_file => options.netrc_file)
    client.auto_paginate = true

    pulls = fetch_pulls_needing_illumos_mail(client, options.repository)
    pulls.each do |pull|
        send_illumos_mail(client, options.repository, pull,
                          options.user, options.password)

        #
        # Since we don't add the "sent" label and remove the "send"
        # label atomically, we need to ensure we successfully add the
        # "sent" label prior to removing the "send" label.
        #
        # If an abnormal event occurs and we end up adding the "sent"
        # label, but not removing the "send" label, this will be handled
        # gracefully and resolved the next time this script runs
        # (see the "fetch_pulls_needing_illumos_mail" function for more
        # details).
        #
        add_mail_sent_label(client, options.repository, pull)
        remove_send_mail_label(client, options.repository, pull)
    end
end

if __FILE__ == $0
    main()
end

# vim: tabstop=4 shiftwidth=4 expandtab textwidth=72 colorcolumn=80
