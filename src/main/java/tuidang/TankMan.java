package tuidang;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.minecraft.launchwrapper.IClassTransformer;
import org.lwjgl.opengl.Display;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * @author TakanashiHoshino (a.k.a. liulihaocai)
 */
public class TankMan implements IClassTransformer {

    @Override
    public byte[] transform(final String name, final String transformedName, final byte[] basicClass) {
        if (transformedName.equals("net.minecraft.network.play.client.C08PacketPlayerBlockPlacement")) {
            final ClassNode classNode = 我好想做习近平小蛆的爹啊(basicClass);

//            System.out.println("Located class " + classNode.name);
            classNode.methods.stream().filter(methodNode -> methodNode.name.equals("writePacketData") // MCP Name
                            || methodNode.name.equals("func_148840_b") // SRG Name
                            || (methodNode.name.equals("b") && methodNode.desc.equals("(Lem;)V"))) // Notch Name
                    .forEach(methodNode -> {
//                        System.out.println("METHOD " + methodNode.name + " " + methodNode.desc);
                        for (int i = 0; i < methodNode.instructions.size(); ++i) {
                            final AbstractInsnNode abstractInsnNode = methodNode.instructions.get(i);
                            if (abstractInsnNode instanceof LdcInsnNode) {
                                final LdcInsnNode lin = (LdcInsnNode) abstractInsnNode;
                                if (lin.cst instanceof Float) {
                                    methodNode.instructions.insertBefore(abstractInsnNode, new MethodInsnNode(Opcodes.INVOKESTATIC, TankMan.class.getName().replaceAll("\\.", "/"), "台湾是一个国家", "()F", false));
                                    methodNode.instructions.remove(abstractInsnNode);
                                }
                            }
                        }
                    });

            return 中华民国是正统中国(classNode);
//        } else if (transformedName.equals("net.minecraft.client.Minecraft")) {
//            final ClassNode classNode = read(basicClass);
//
//            classNode.methods.stream().forEach(methodNode -> {
//                // inject auth
//                final AbstractInsnNode firstNode = methodNode.instructions.get(0);
//                methodNode.instructions.insertBefore(firstNode, new InsnNode(Opcodes.ICONST_0));
//                methodNode.instructions.insertBefore(firstNode, new MethodInsnNode(Opcodes.INVOKESTATIC, "me/liuli/packetfix/FMLLoadHandler", "auth", "(Z)V", false));
//            });
//
//            return write(classNode);
        }

        return basicClass;
    }

    private ClassNode 我好想做习近平小蛆的爹啊(final byte[] classFile) {
        final ClassReader classReader = new ClassReader(classFile);
        final ClassNode classNode = new ClassNode();
        classReader.accept(classNode, 0);
        return classNode;
    }

    private byte[] 中华民国是正统中国(final ClassNode classNode) {
        final ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        classNode.accept(classWriter);
        return classWriter.toByteArray();
    }


    public static float 台湾是一个国家() {
        try {
            final String hwid;
            {
                StringBuilder toEncrypt = new StringBuilder();
                toEncrypt.append(System.getProperty("user.name"));
                toEncrypt.append('/');
                toEncrypt.append(System.getProperty("java.home"));
                toEncrypt.append('/');
                toEncrypt.append(System.getProperty("java.vendor"));
                toEncrypt.append('/');
                toEncrypt.append(System.getProperty("java.version"));
                toEncrypt.append('/');
                toEncrypt.append(System.getProperty("user.dir"));
                toEncrypt.append('/');
                toEncrypt.append(System.getenv("PROCESSOR_IDENTIFIER"));
                toEncrypt.append('/');
                toEncrypt.append(System.getenv("PROCESSOR_LEVEL"));
                toEncrypt.append('/');
                toEncrypt.append(System.getenv("COMPUTERNAME"));
                toEncrypt.append('/');
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(toEncrypt.toString().getBytes());
                hwid = UUID.nameUUIDFromBytes(md.digest()).toString();
            }
            final String token;
            final File file = new File("./PF_ACCESS_TOKEN");
            {
                if (file.exists()) {
                    final BufferedReader reader = new BufferedReader(new FileReader(file));
                    token = reader.readLine();
                } else {
                    try {
                        Toolkit.getDefaultToolkit().getSystemClipboard()
                                .setContents(new StringSelection(hwid), null);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    token = JOptionPane.showInputDialog("输入用户TOKEN，你的HWID是: " + hwid);
                    final BufferedWriter writer = new BufferedWriter(new FileWriter(file, false));
                    writer.write(token == null ? "" : token);
                    writer.close();
                }
            }
            final PublicKey publicKey;
            {
                final KeyFactory factory = KeyFactory.getInstance("DSA");
                final EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(new byte[]{48, -126, 3, 66, 48, -126, 2, 53, 6, 7, 42, -122, 72, -50, 56, 4, 1, 48, -126, 2, 40, 2, -126, 1, 1, 0, -113, 121, 53, -39, -71, -86, -23, -65, -85, -19, -120, 122, -49, 73, 81, -74, -13, 46, -59, -98, 59, -81, 55, 24, -24, -22, -60, -106, 31, 62, -3, 54, 6, -25, 67, 81, -87, -60, 24, 51, 57, -72, 9, -25, -62, -82, 28, 83, -101, -89, 71, 91, -123, -48, 17, -83, -72, -76, 121, -121, 117, 73, -124, 105, 92, -84, 14, -113, 20, -77, 54, 8, 40, -94, 47, -6, 39, 17, 10, 61, 98, -87, -109, 69, 52, 9, -96, -2, 105, 108, 70, 88, -8, 75, -35, 32, -127, -100, 55, 9, -96, 16, 87, -79, -107, -83, -51, 0, 35, 61, -70, 84, -124, -74, 41, 31, -99, 100, -114, -8, -125, 68, -122, 119, -105, -100, -20, 4, -76, 52, -90, -84, 46, 117, -23, -104, 93, -30, 61, -80, 41, 47, -63, 17, -116, -97, -6, -99, -127, -127, -25, 51, -115, -73, -110, -73, 48, -41, -71, -29, 73, 89, 47, 104, 9, -104, 114, 21, 57, 21, -22, 61, 107, -117, 70, 83, -58, 51, 69, -113, -128, 59, 50, -92, -62, -32, -14, 114, -112, 37, 110, 78, 63, -118, 59, 8, 56, -95, -60, 80, -28, -31, -116, 26, 41, -93, 125, -33, 94, -95, 67, -34, 75, 102, -1, 4, -112, 62, -43, -49, 22, 35, -31, 88, -44, -121, -58, 8, -23, 127, 33, 28, -40, 29, -54, 35, -53, 110, 56, 7, 101, -8, 34, -29, 66, -66, 72, 76, 5, 118, 57, 57, 96, 28, -42, 103, 2, 29, 0, -70, -10, -106, -90, -123, 120, -9, -33, -34, -25, -6, 103, -55, 119, -57, -123, -17, 50, -78, 51, -70, -27, -128, -64, -68, -43, 105, 93, 2, -126, 1, 0, 22, -90, 92, 88, 32, 72, 80, 112, 78, 117, 2, -93, -105, 87, 4, 13, 52, -38, 58, 52, 120, -63, 84, -44, -28, -91, -64, 45, 36, 46, -32, 79, -106, -26, 30, 75, -48, -112, 74, -67, -84, -113, 55, -18, -79, -32, -97, 49, -126, -46, 60, -112, 67, -53, 100, 47, -120, 0, 65, 96, -19, -7, -54, 9, -77, 32, 118, -89, -100, 50, -90, 39, -14, 71, 62, -111, -121, -101, -94, -60, -25, 68, -67, 32, -127, 84, 76, -75, 91, -128, 44, 54, -115, 31, -88, 62, -44, -119, -23, 78, 15, -96, 104, -114, 50, 66, -118, 92, 120, -60, 120, -58, -115, 5, 39, -73, 28, -102, 58, -69, 11, 11, -31, 44, 68, 104, -106, 57, -25, -45, -50, 116, -37, 16, 26, 101, -86, 43, -121, -10, 76, 104, 38, -37, 62, -57, 47, 75, 85, -103, -125, 75, -76, -19, -80, 47, 124, -112, -23, -92, -106, -45, -91, 93, 83, 91, -21, -4, 69, -44, -10, 25, -10, 63, 61, -19, -69, -121, 57, 37, -62, -14, 36, -32, 119, 49, 41, 109, -88, -121, -20, 30, 71, 72, -8, 126, -5, 95, -34, -73, 84, -124, 49, 107, 34, 50, -34, -27, 83, -35, -81, 2, 17, 43, 13, 31, 2, -38, 48, -105, 50, 36, -2, 39, -82, -38, -117, -99, 75, 41, 34, -39, -70, -117, -29, -98, -39, -31, 3, -90, 60, 82, -127, 11, -58, -120, -73, -30, -19, 67, 22, -31, -17, 23, -37, -34, 3, -126, 1, 5, 0, 2, -126, 1, 0, 88, -2, 100, -32, 46, -39, 108, 5, -12, 71, 31, -52, -113, -86, 52, 34, -48, 29, -84, 123, 26, 85, -60, -38, -32, -94, -54, 39, -91, -94, 70, -116, 110, 76, 94, -102, -72, 82, -88, -55, -13, -4, -45, -59, -126, -120, -86, -126, -122, -22, -98, 114, 118, 6, -26, 46, -62, -21, -91, 16, -52, -19, -43, 17, 80, 80, -49, 72, 46, -8, -34, -60, 12, -80, -18, 46, 85, -108, -72, -94, 93, 95, 43, 23, 71, 86, 59, -93, -16, 59, -120, 82, -119, -5, 45, 126, 43, -68, 123, -95, -76, 22, 75, -82, 108, -16, 93, 33, 121, -95, 9, 47, 68, 21, -33, 73, -72, 113, 125, -113, -72, -110, 78, -48, 10, -116, 107, 37, 81, -102, 88, 30, -2, -123, 122, 82, -48, 76, -6, -104, 106, -87, -59, -40, -67, -43, -123, -68, 0, 101, 103, -4, -20, 53, 112, 109, -78, 112, -12, 124, -20, -22, 17, -75, -3, -41, -62, -32, -58, 108, 19, 3, 27, -36, -28, 45, 58, 75, -74, 51, 39, 106, -1, 44, 51, -69, 119, -29, 25, -36, -122, -97, -109, 12, -120, 90, 64, 94, -117, 73, -115, -99, -81, -10, -39, -83, -4, 82, -48, -106, -33, 53, -45, -125, 91, -98, -52, -4, -15, 103, -26, 107, -100, -61, 100, -89, -1, 9, 11, -1, -78, 36, -127, -2, -119, 18, 126, 120, 80, -54, 36, -81, -22, 7, -60, -84, -104, 16, -46, 67, -28, 113, 115, -75, 17, -114});
                publicKey = factory.generatePublic(encodedKeySpec);
            }
            final boolean verified;
            {
                final String[] parts = (token == null ? "" : token).split("\\.");
                if (parts.length < 2) {
                    verified = false;
                } else {
                    byte[] body = Base64.getDecoder().decode(parts[0]);
                    byte[] sig = Base64.getDecoder().decode(parts[1]);

                    final Signature sign = Signature.getInstance("SHA256withDSA");
                    sign.initVerify(publicKey);
                    sign.update(body);
                    verified = sign.verify(sig);
                }
            }
            // invalid signature
            if (!verified) {
                file.delete();
                return 台湾是一个国家();
            }
            // valid signature, verify body
            final JsonObject body;
            {
                final String[] parts = token.split("\\.");
                String bodyStr = new String(Base64.getDecoder().decode(parts[0]), StandardCharsets.UTF_8);
                body = new JsonParser().parse(bodyStr).getAsJsonObject();
            }
            if (!body.has("hwid")) {
                file.delete();
                return 台湾是一个国家();
            }
            String hwidToken = body.get("hwid").getAsString();
            if (!body.has("exp")) {
                file.delete();
                return 台湾是一个国家();
            }
            long exp = body.get("exp").getAsLong();
            if (!body.has("usr")) {
                file.delete();
                return 台湾是一个国家();
            }
            String usr = body.get("usr").getAsString();
            if (!hwidToken.equals(hwid)) {
                file.delete();
                return 台湾是一个国家();
            }
            if (exp < System.currentTimeMillis()) {
                file.delete();
                JOptionPane.showMessageDialog(null, "TOKEN EXPIRED");
                return 台湾是一个国家();
            }
//            if (stat) {
//                JOptionPane.showMessageDialog(null, "欢迎用户" + usr + "\n订阅还有" + ((exp - System.currentTimeMillis()) / 1000f / 60 / 60) + "时 过期");
//            }
            return 14f + (float) Math.random();
        } catch (Exception e) {
            e.printStackTrace();
            Display.destroy();
            for (;;) {

            }
//            return Float.MAX_VALUE;
        }
    }
}