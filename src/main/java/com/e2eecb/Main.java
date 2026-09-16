package com.e2eecb;

import com.e2eecb.crypto.ChatUser;
import com.e2eecb.crypto.DoubleRatchet;
import com.e2eecb.crypto.InitialMessage;
import com.e2eecb.crypto.PreKeyBundle;
import com.e2eecb.server.InMemoryDirectory;

import java.nio.charset.StandardCharsets;

public class Main {

    public static void main(String[] args) {
        InMemoryDirectory directory = new InMemoryDirectory();

        ChatUser alice = new ChatUser("alice");
        ChatUser bob = new ChatUser("bob");

        directory.publish(alice.publishBundle());
        directory.publish(bob.publishBundle());

        PreKeyBundle bobBundle = directory.fetch("bob");
        InitialMessage initialMessage = alice.startSession("bob", bobBundle, "Hey Bob, this is Alice".getBytes(StandardCharsets.UTF_8));

        byte[] bobDecrypted = bob.acceptSession("alice", initialMessage);
        System.out.println("Bob received: " + new String(bobDecrypted, StandardCharsets.UTF_8));

        DoubleRatchet.EncryptedMessage reply1 = bob.send("alice", "Hi Alice, Bob here".getBytes(StandardCharsets.UTF_8));
        byte[] aliceDecrypted1 = alice.receive("bob", reply1);
        System.out.println("Alice received: " + new String(aliceDecrypted1, StandardCharsets.UTF_8));

        DoubleRatchet.EncryptedMessage msg2 = alice.send("bob", "Great, encryption works".getBytes(StandardCharsets.UTF_8));
        byte[] bobDecrypted2 = bob.receive("alice", msg2);
        System.out.println("Bob received: " + new String(bobDecrypted2, StandardCharsets.UTF_8));

        DoubleRatchet.EncryptedMessage msg3 = alice.send("bob", "Second message before Bob replies".getBytes(StandardCharsets.UTF_8));
        DoubleRatchet.EncryptedMessage msg4 = alice.send("bob", "Third message, out of order test".getBytes(StandardCharsets.UTF_8));

        byte[] bobDecrypted4 = bob.receive("alice", msg4);
        byte[] bobDecrypted3 = bob.receive("alice", msg3);
        System.out.println("Bob received out of order, msg4 first: " + new String(bobDecrypted4, StandardCharsets.UTF_8));
        System.out.println("Bob received out of order, msg3 second: " + new String(bobDecrypted3, StandardCharsets.UTF_8));
    }
}
