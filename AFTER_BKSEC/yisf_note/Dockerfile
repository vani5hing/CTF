FROM ubuntu:22.04@sha256:adbb90115a21969d2fe6fa7f9af4253e16d45f8d4c1e930182610c4731962658
ENV user yisf_note
ENV chall_port 31337

RUN apt-get update
RUN apt-get -y install socat

RUN adduser $user

ADD ./flag /home/$user/flag
ADD ./$user /home/$user/$user

RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD socat -T 90 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user
