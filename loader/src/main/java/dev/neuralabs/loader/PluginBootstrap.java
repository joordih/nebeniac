package dev.neuralabs.loader;

import java.io.File;
import java.lang.reflect.Constructor;
import org.bukkit.plugin.PluginDescriptionFile;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.plugin.java.JavaPluginLoader;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

public final class PluginBootstrap {
  private static final String JAVA_PLUGIN = Type.getInternalName(JavaPlugin.class);
  private static final String BOOTSTRAP = Type.getInternalName(PluginBootstrap.class);
  private static final String STANDALONE_CONSTRUCTOR = Type.getMethodDescriptor(
      Type.VOID_TYPE,
      Type.getType(JavaPluginLoader.class),
      Type.getType(PluginDescriptionFile.class),
      Type.getType(File.class),
      Type.getType(File.class));

  private static final ThreadLocal<Context> CONTEXT = new ThreadLocal<>();

  private PluginBootstrap() {}

  static <T extends JavaPlugin> T instantiate(
      Class<T> pluginClass,
      JavaPluginLoader loader,
      PluginDescriptionFile description,
      File dataFolder,
      File file) throws ReflectiveOperationException {
    CONTEXT.set(new Context(loader, description, dataFolder, file));
    try {
      Constructor<T> constructor = pluginClass.getDeclaredConstructor();
      constructor.setAccessible(true);
      return constructor.newInstance();
    } finally {
      CONTEXT.remove();
    }
  }

  static byte[] redirectPluginConstructor(byte[] classBytes) {
    ClassReader reader = new ClassReader(classBytes);
    if (!JAVA_PLUGIN.equals(reader.getSuperName())) {
      return classBytes;
    }

    ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
    reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
      @Override
      public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
                                       String[] exceptions) {
        MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
        return "<init>".equals(name) ? new SuperConstructorRedirect(delegate) : delegate;
      }
    }, 0);
    return writer.toByteArray();
  }

  public static JavaPluginLoader loader() {
    return context().loader;
  }

  public static PluginDescriptionFile description() {
    return context().description;
  }

  public static File dataFolder() {
    return context().dataFolder;
  }

  public static File file() {
    return context().file;
  }

  private static Context context() {
    Context context = CONTEXT.get();
    if (context == null) {
      throw new IllegalStateException("Protected plugins can only be constructed by SecurePluginLoader");
    }
    return context;
  }

  private static final class SuperConstructorRedirect extends MethodVisitor {
    SuperConstructorRedirect(MethodVisitor delegate) {
      super(Opcodes.ASM9, delegate);
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
      if (opcode == Opcodes.INVOKESPECIAL && JAVA_PLUGIN.equals(owner)
          && "<init>".equals(name) && "()V".equals(descriptor)) {
        pushContext("loader", JavaPluginLoader.class);
        pushContext("description", PluginDescriptionFile.class);
        pushContext("dataFolder", File.class);
        pushContext("file", File.class);
        super.visitMethodInsn(Opcodes.INVOKESPECIAL, JAVA_PLUGIN, "<init>", STANDALONE_CONSTRUCTOR, false);
        return;
      }
      super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }

    private void pushContext(String accessor, Class<?> type) {
      super.visitMethodInsn(Opcodes.INVOKESTATIC, BOOTSTRAP, accessor,
          Type.getMethodDescriptor(Type.getType(type)), false);
    }
  }

  private static final class Context {
    final JavaPluginLoader loader;
    final PluginDescriptionFile description;
    final File dataFolder;
    final File file;

    Context(JavaPluginLoader loader, PluginDescriptionFile description, File dataFolder, File file) {
      this.loader = loader;
      this.description = description;
      this.dataFolder = dataFolder;
      this.file = file;
    }
  }
}
